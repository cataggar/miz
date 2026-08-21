//! Host-side QEMU executable and UEFI firmware discovery/materialization.

const std = @import("std");
const builtin = @import("builtin");
const bzip2 = @import("bzip2.zig");

const Io = std.Io;
const max_firmware_size: u64 = 128 * 1024 * 1024;

pub const GuestArchitecture = enum {
    x86_64,
    aarch64,

    pub fn cliName(self: GuestArchitecture) []const u8 {
        return switch (self) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
        };
    }
};

pub const FirmwareEncoding = enum {
    raw,
    bzip2,
};

pub const FirmwareSource = struct {
    path: []u8,
    encoding: FirmwareEncoding,

    pub fn deinit(self: *FirmwareSource, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const FirmwareSourcePair = struct {
    code: FirmwareSource,
    vars: FirmwareSource,

    pub fn deinit(self: *FirmwareSourcePair, allocator: std.mem.Allocator) void {
        self.code.deinit(allocator);
        self.vars.deinit(allocator);
        self.* = undefined;
    }
};

pub const FirmwarePair = struct {
    code_path: []u8,
    vars_path: []u8,

    pub fn deinit(self: *FirmwarePair, allocator: std.mem.Allocator) void {
        allocator.free(self.code_path);
        allocator.free(self.vars_path);
        self.* = undefined;
    }
};

pub const FirmwareSearchOptions = struct {
    architecture: GuestArchitecture = .x86_64,
    secure_boot: bool = false,
    explicit_code_path: ?[]const u8 = null,
    explicit_vars_path: ?[]const u8 = null,
    qemu_path: ?[]const u8 = null,
    data_dirs: []const []const u8 = &.{},
    include_system_candidates: bool = true,
};

pub const MaterializeOptions = struct {
    max_output_size: u64 = max_firmware_size,
};

const FirmwareCandidate = struct {
    code: []const u8,
    vars: []const u8,
};

const x86_data_candidates = [_]FirmwareCandidate{
    .{ .code = "edk2-x86_64-code.fd", .vars = "edk2-i386-vars.fd" },
    .{ .code = "OVMF_CODE.fd", .vars = "OVMF_VARS.fd" },
    .{ .code = "OVMF_CODE_4M.fd", .vars = "OVMF_VARS_4M.fd" },
};

const x86_secure_boot_data_candidates = [_]FirmwareCandidate{
    .{ .code = "OVMF_CODE_4M.secboot.fd", .vars = "OVMF_VARS_4M.ms.fd" },
    .{ .code = "OVMF_CODE_4M.ms.fd", .vars = "OVMF_VARS_4M.ms.fd" },
    .{ .code = "OVMF_CODE.secboot.fd", .vars = "OVMF_VARS.secboot.fd" },
};

const aarch64_data_candidates = [_]FirmwareCandidate{
    .{ .code = "edk2-aarch64-code.fd", .vars = "edk2-arm-vars.fd" },
    .{ .code = "AAVMF_CODE.no-secboot.fd", .vars = "AAVMF_VARS.fd" },
    .{ .code = "AAVMF_CODE.fd", .vars = "AAVMF_VARS.fd" },
    .{ .code = "AAVMF_CODE_4M.fd", .vars = "AAVMF_VARS_4M.fd" },
    .{ .code = "QEMU_EFI.fd", .vars = "AAVMF_VARS.fd" },
    .{ .code = "QEMU_EFI.fd", .vars = "vars.fd" },
    .{ .code = "QEMU_EFI-pflash.raw", .vars = "vars-template-pflash.raw" },
    .{ .code = "code.fd", .vars = "vars.fd" },
};

const aarch64_secure_boot_data_candidates = [_]FirmwareCandidate{
    .{ .code = "AAVMF_CODE.secboot.fd", .vars = "AAVMF_VARS.ms.fd" },
    .{ .code = "AAVMF_CODE.ms.fd", .vars = "AAVMF_VARS.ms.fd" },
};

const linux_x86_candidates = [_]FirmwareCandidate{
    .{ .code = "/usr/share/OVMF/OVMF_CODE.fd", .vars = "/usr/share/OVMF/OVMF_VARS.fd" },
    .{ .code = "/usr/share/OVMF/OVMF_CODE_4M.fd", .vars = "/usr/share/OVMF/OVMF_VARS_4M.fd" },
    .{ .code = "/usr/share/edk2/ovmf/OVMF_CODE.fd", .vars = "/usr/share/edk2/ovmf/OVMF_VARS.fd" },
    .{ .code = "/usr/share/edk2/x64/OVMF_CODE.fd", .vars = "/usr/share/edk2/x64/OVMF_VARS.fd" },
    .{ .code = "/usr/share/qemu/edk2-x86_64-code.fd", .vars = "/usr/share/qemu/edk2-i386-vars.fd" },
};

const linux_x86_secure_boot_candidates = [_]FirmwareCandidate{
    .{ .code = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd", .vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd" },
    .{ .code = "/usr/share/OVMF/OVMF_CODE_4M.ms.fd", .vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd" },
    .{ .code = "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd", .vars = "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd" },
};

const macos_x86_candidates = [_]FirmwareCandidate{
    .{ .code = "/opt/homebrew/share/qemu/edk2-x86_64-code.fd", .vars = "/opt/homebrew/share/qemu/edk2-i386-vars.fd" },
    .{ .code = "/usr/local/share/qemu/edk2-x86_64-code.fd", .vars = "/usr/local/share/qemu/edk2-i386-vars.fd" },
    .{ .code = "/opt/local/share/qemu/edk2-x86_64-code.fd", .vars = "/opt/local/share/qemu/edk2-i386-vars.fd" },
};

const linux_aarch64_candidates = [_]FirmwareCandidate{
    .{ .code = "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd", .vars = "/usr/share/AAVMF/AAVMF_VARS.fd" },
    .{ .code = "/usr/share/AAVMF/AAVMF_CODE.fd", .vars = "/usr/share/AAVMF/AAVMF_VARS.fd" },
    .{ .code = "/usr/share/AAVMF/AAVMF_CODE_4M.fd", .vars = "/usr/share/AAVMF/AAVMF_VARS_4M.fd" },
    .{ .code = "/usr/share/edk2/aarch64/QEMU_EFI.fd", .vars = "/usr/share/edk2/arm-vars.fd" },
    .{ .code = "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw", .vars = "/usr/share/edk2/aarch64/vars-template-pflash.raw" },
    .{ .code = "/usr/share/edk2/aarch64/AAVMF_CODE.fd", .vars = "/usr/share/edk2/aarch64/AAVMF_VARS.fd" },
    .{ .code = "/usr/share/edk2/aarch64/edk2-aarch64-code.fd", .vars = "/usr/share/edk2/aarch64/edk2-arm-vars.fd" },
    .{ .code = "/usr/share/edk2/aarch64/code.fd", .vars = "/usr/share/edk2/aarch64/vars.fd" },
    .{ .code = "/usr/share/qemu/edk2-aarch64-code.fd", .vars = "/usr/share/qemu/edk2-arm-vars.fd" },
};

const linux_aarch64_secure_boot_candidates = [_]FirmwareCandidate{
    .{ .code = "/usr/share/AAVMF/AAVMF_CODE.secboot.fd", .vars = "/usr/share/AAVMF/AAVMF_VARS.ms.fd" },
    .{ .code = "/usr/share/AAVMF/AAVMF_CODE.ms.fd", .vars = "/usr/share/AAVMF/AAVMF_VARS.ms.fd" },
};

const macos_aarch64_candidates = [_]FirmwareCandidate{
    .{ .code = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd", .vars = "/opt/homebrew/share/qemu/edk2-arm-vars.fd" },
    .{ .code = "/usr/local/share/qemu/edk2-aarch64-code.fd", .vars = "/usr/local/share/qemu/edk2-arm-vars.fd" },
    .{ .code = "/opt/local/share/qemu/edk2-aarch64-code.fd", .vars = "/opt/local/share/qemu/edk2-arm-vars.fd" },
};

pub fn pathAccessible(io: Io, path: []const u8, options: Io.Dir.AccessOptions) !bool {
    Io.Dir.cwd().access(io, path, options) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.PermissionDenied => return false,
        else => return err,
    };
    return true;
}

pub fn executableName(comptime base: []const u8) []const u8 {
    return if (builtin.os.tag == .windows) base ++ ".exe" else base;
}

pub fn qemuSystemName(architecture: GuestArchitecture) []const u8 {
    return switch (architecture) {
        .x86_64 => executableName("qemu-system-x86_64"),
        .aarch64 => executableName("qemu-system-aarch64"),
    };
}

pub fn findExecutableInPathAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    name: []const u8,
) !?[]u8 {
    const path_value = environ.getAlloc(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableMissing => return null,
        else => return err,
    };
    defer allocator.free(path_value);
    return findExecutableInPathValueAlloc(allocator, io, path_value, name);
}

pub fn findExecutableInPathValueAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    path_value: []const u8,
    name: []const u8,
) !?[]u8 {
    const suffix: []const u8 = if (builtin.os.tag == .windows and
        !(name.len >= 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".exe")))
        ".exe"
    else
        "";

    var it = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (it.next()) |dir_path| {
        const candidate = if (dir_path.len == 0)
            try std.fmt.allocPrint(allocator, "{s}{s}", .{ name, suffix })
        else
            try std.fmt.allocPrint(
                allocator,
                "{s}{c}{s}{s}",
                .{ dir_path, std.fs.path.sep, name, suffix },
            );
        errdefer allocator.free(candidate);

        if (try pathAccessible(io, candidate, .{ .execute = true })) return candidate;
        allocator.free(candidate);
    }

    return null;
}

pub fn findFirmwareSourcePairAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    options: FirmwareSearchOptions,
) !?FirmwareSourcePair {
    if (options.explicit_code_path != null or options.explicit_vars_path != null) {
        if (options.explicit_code_path == null or options.explicit_vars_path == null)
            return error.IncompleteFirmwareOverride;

        if (!try regularFileReadable(io, options.explicit_code_path.?) or
            !try regularFileReadable(io, options.explicit_vars_path.?))
        {
            return error.FirmwareNotReadable;
        }
        if (options.secure_boot and
            !firmwareCodeNameIndicatesSecureBoot(options.explicit_code_path.?))
        {
            return error.FirmwareNotSecureBootCapable;
        }

        return @as(?FirmwareSourcePair, try ownedSourcePairAlloc(
            allocator,
            options.explicit_code_path.?,
            options.explicit_vars_path.?,
            .raw,
        ));
    }

    if (try findAutomaticFirmwareSourceAlloc(allocator, io, options, .raw)) |pair|
        return pair;
    return findAutomaticFirmwareSourceAlloc(allocator, io, options, .bzip2);
}

/// Compatibility helper for existing callers that require raw firmware paths.
pub fn findFirmwarePairAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    options: FirmwareSearchOptions,
) !?FirmwarePair {
    var sources = try findFirmwareSourcePairAlloc(allocator, io, options) orelse
        return null;
    defer sources.deinit(allocator);
    if (sources.code.encoding != .raw or sources.vars.encoding != .raw) return null;

    const code_path = try allocator.dupe(u8, sources.code.path);
    errdefer allocator.free(code_path);
    return .{
        .code_path = code_path,
        .vars_path = try allocator.dupe(u8, sources.vars.path),
    };
}

fn findAutomaticFirmwareSourceAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    options: FirmwareSearchOptions,
    encoding: FirmwareEncoding,
) !?FirmwareSourcePair {
    for (options.data_dirs) |data_dir| {
        if (try findFirmwareInDataDirAlloc(
            allocator,
            io,
            data_dir,
            options.architecture,
            options.secure_boot,
            encoding,
        )) |pair| return pair;
    }

    if (options.qemu_path) |qemu_path| {
        if (std.fs.path.dirname(qemu_path)) |bin_dir| {
            const adjacent_share = try std.fs.path.join(allocator, &.{ bin_dir, "share" });
            defer allocator.free(adjacent_share);
            if (try findFirmwareInDataDirAlloc(
                allocator,
                io,
                adjacent_share,
                options.architecture,
                options.secure_boot,
                encoding,
            )) |pair| return pair;

            if (std.fs.path.dirname(bin_dir)) |prefix| {
                const prefix_share = try std.fs.path.join(allocator, &.{ prefix, "share", "qemu" });
                defer allocator.free(prefix_share);
                if (try findFirmwareInDataDirAlloc(
                    allocator,
                    io,
                    prefix_share,
                    options.architecture,
                    options.secure_boot,
                    encoding,
                )) |pair| return pair;
            }
        }
    }

    if (options.include_system_candidates) {
        for (systemFirmwareCandidates(
            options.architecture,
            options.secure_boot,
        )) |candidate| {
            if (try readableEncodedPairAlloc(
                allocator,
                io,
                candidate.code,
                candidate.vars,
                encoding,
            )) |pair| return pair;
        }
    }
    return null;
}

fn systemFirmwareCandidates(
    architecture: GuestArchitecture,
    secure_boot: bool,
) []const FirmwareCandidate {
    if (secure_boot) {
        return switch (architecture) {
            .x86_64 => switch (builtin.os.tag) {
                .linux => &linux_x86_secure_boot_candidates,
                else => &.{},
            },
            .aarch64 => switch (builtin.os.tag) {
                .linux => &linux_aarch64_secure_boot_candidates,
                else => &.{},
            },
        };
    }
    return switch (architecture) {
        .x86_64 => switch (builtin.os.tag) {
            .linux => &linux_x86_candidates,
            .macos => &macos_x86_candidates,
            else => &.{},
        },
        .aarch64 => switch (builtin.os.tag) {
            .linux => &linux_aarch64_candidates,
            .macos => &macos_aarch64_candidates,
            else => &.{},
        },
    };
}

fn dataFirmwareCandidates(
    architecture: GuestArchitecture,
    secure_boot: bool,
) []const FirmwareCandidate {
    if (secure_boot) {
        return switch (architecture) {
            .x86_64 => &x86_secure_boot_data_candidates,
            .aarch64 => &aarch64_secure_boot_data_candidates,
        };
    }
    return switch (architecture) {
        .x86_64 => &x86_data_candidates,
        .aarch64 => &aarch64_data_candidates,
    };
}

fn findFirmwareInDataDirAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    data_dir: []const u8,
    architecture: GuestArchitecture,
    secure_boot: bool,
    encoding: FirmwareEncoding,
) !?FirmwareSourcePair {
    for (dataFirmwareCandidates(architecture, secure_boot)) |candidate| {
        const code_base = try std.fs.path.join(allocator, &.{ data_dir, candidate.code });
        defer allocator.free(code_base);
        const vars_base = try std.fs.path.join(allocator, &.{ data_dir, candidate.vars });
        defer allocator.free(vars_base);

        if (try readableEncodedPairAlloc(
            allocator,
            io,
            code_base,
            vars_base,
            encoding,
        )) |pair| return pair;
    }

    return null;
}

fn firmwareCodeNameIndicatesSecureBoot(path: []const u8) bool {
    const name = std.fs.path.basename(path);
    return std.ascii.indexOfIgnoreCase(name, "secboot") != null or
        std.ascii.indexOfIgnoreCase(name, ".ms.") != null;
}

fn readableEncodedPairAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    code_base: []const u8,
    vars_base: []const u8,
    encoding: FirmwareEncoding,
) !?FirmwareSourcePair {
    const code_path = try encodedPathAlloc(allocator, code_base, encoding);
    defer allocator.free(code_path);
    const vars_path = try encodedPathAlloc(allocator, vars_base, encoding);
    defer allocator.free(vars_path);

    if (!try regularFileReadable(io, code_path) or
        !try regularFileReadable(io, vars_path))
    {
        return null;
    }
    return @as(
        ?FirmwareSourcePair,
        try ownedSourcePairAlloc(allocator, code_path, vars_path, encoding),
    );
}

fn encodedPathAlloc(
    allocator: std.mem.Allocator,
    base: []const u8,
    encoding: FirmwareEncoding,
) ![]u8 {
    return switch (encoding) {
        .raw => allocator.dupe(u8, base),
        .bzip2 => std.fmt.allocPrint(allocator, "{s}.bz2", .{base}),
    };
}

fn ownedSourcePairAlloc(
    allocator: std.mem.Allocator,
    code_path: []const u8,
    vars_path: []const u8,
    encoding: FirmwareEncoding,
) !FirmwareSourcePair {
    const owned_code = try allocator.dupe(u8, code_path);
    errdefer allocator.free(owned_code);
    return .{
        .code = .{ .path = owned_code, .encoding = encoding },
        .vars = .{
            .path = try allocator.dupe(u8, vars_path),
            .encoding = encoding,
        },
    };
}

fn regularFileReadable(io: Io, path: []const u8) !bool {
    const path_stat = Io.Dir.cwd().statFile(io, path, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.PermissionDenied => return false,
        else => return err,
    };
    if (path_stat.kind != .file or path_stat.size == 0) return false;

    const file = Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.PermissionDenied, error.IsDir => return false,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    return sameFileSnapshot(path_stat, stat);
}

const DestinationState = enum {
    missing,
    valid,
};

fn destinationState(io: Io, path: []const u8) !DestinationState {
    const stat = Io.Dir.cwd().statFile(io, path, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };
    if (stat.kind != .file) return error.FirmwareDestinationNotRegularFile;
    if (stat.size == 0) return error.FirmwareDestinationEmpty;
    if (!try pathAccessible(io, path, .{ .read = true }))
        return error.FirmwareDestinationNotReadable;
    return .valid;
}

pub fn requireFirmwareWritable(io: Io, path: []const u8) !void {
    if (try destinationState(io, path) != .valid)
        return error.FirmwareDestinationMissing;
    if (!try pathAccessible(io, path, .{ .write = true }))
        return error.FirmwareDestinationNotWritable;
}

pub fn materializeFirmwarePairAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    source: FirmwareSourcePair,
    code_path: []const u8,
    vars_path: []const u8,
    options: MaterializeOptions,
) !FirmwarePair {
    const code_state = try destinationState(io, code_path);
    const vars_state = try destinationState(io, vars_path);

    if (code_state == .missing)
        try materializeFirmwareFile(io, source.code, code_path, options);
    if (vars_state == .missing)
        try materializeFirmwareFile(io, source.vars, vars_path, options);

    _ = try destinationState(io, code_path);
    _ = try destinationState(io, vars_path);
    const owned_code = try allocator.dupe(u8, code_path);
    errdefer allocator.free(owned_code);
    return .{
        .code_path = owned_code,
        .vars_path = try allocator.dupe(u8, vars_path),
    };
}

pub fn materializeFirmwareFile(
    io: Io,
    source: FirmwareSource,
    destination_path: []const u8,
    options: MaterializeOptions,
) !void {
    _ = try materializeFirmwareFileCreated(
        io,
        source,
        destination_path,
        options,
    );
}

pub fn materializeFirmwareFileCreated(
    io: Io,
    source: FirmwareSource,
    destination_path: []const u8,
    options: MaterializeOptions,
) !bool {
    if (options.max_output_size == 0) return error.FirmwareTooLarge;
    if (try destinationState(io, destination_path) == .valid) return false;

    const source_path_stat = try Io.Dir.cwd().statFile(io, source.path, .{
        .follow_symlinks = false,
    });
    if (source_path_stat.kind != .file) return error.FirmwareSourceNotRegularFile;
    if (source_path_stat.size == 0) return error.FirmwareSourceEmpty;

    const source_file = try Io.Dir.cwd().openFile(io, source.path, .{
        .mode = .read_only,
        .allow_directory = false,
    });
    defer source_file.close(io);
    const source_stat = try source_file.stat(io);
    if (!sameFileSnapshot(source_path_stat, source_stat))
        return error.FirmwareSourceChanged;

    var stage = try Io.Dir.cwd().createFileAtomic(io, destination_path, .{});
    defer stage.deinit(io);

    const output_size = switch (source.encoding) {
        .raw => try copyRawFirmware(
            io,
            source_file,
            source_stat.size,
            stage.file,
            options.max_output_size,
        ),
        .bzip2 => try decompressBzip2Firmware(
            io,
            source_file,
            source_stat.size,
            stage.file,
            options.max_output_size,
        ),
    };
    if (output_size == 0) return error.FirmwareDestinationEmpty;
    try stage.file.sync(io);

    const final_path_stat = Io.Dir.cwd().statFile(io, source.path, .{
        .follow_symlinks = false,
    }) catch return error.FirmwareSourceChanged;
    if (!sameFileSnapshot(source_stat, try source_file.stat(io)) or
        !sameFileSnapshot(source_stat, final_path_stat))
        return error.FirmwareSourceChanged;

    stage.link(io) catch |err| switch (err) {
        error.PathAlreadyExists => {
            if (try destinationState(io, destination_path) != .valid)
                return error.FirmwareDestinationInvalid;
            return false;
        },
        else => return err,
    };
    return true;
}

fn copyRawFirmware(
    io: Io,
    source: Io.File,
    source_size: u64,
    destination: Io.File,
    max_output_size: u64,
) !u64 {
    if (source_size > max_output_size) return error.FirmwareTooLarge;
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < source_size) {
        const length: usize = @intCast(@min(source_size - offset, buffer.len));
        const read = try source.readPositionalAll(io, buffer[0..length], offset);
        if (read != length) return error.FirmwareSourceShortRead;
        try destination.writePositionalAll(io, buffer[0..length], offset);
        offset += length;
    }
    return offset;
}

fn decompressBzip2Firmware(
    io: Io,
    source: Io.File,
    source_size: u64,
    destination: Io.File,
    max_output_size: u64,
) !u64 {
    var input_buffer: [64 * 1024]u8 = undefined;
    var source_reader = source.reader(io, &input_buffer);
    var limited_reader = source_reader.interface.limited(
        .limited64(source_size),
        &.{},
    );
    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = destination.writer(io, &output_buffer);
    try bzip2.decompressStream(
        std.heap.page_allocator,
        &limited_reader.interface,
        &output_writer.interface,
        max_output_size,
    );
    try output_writer.interface.flush();
    return output_writer.logicalPos();
}

fn sameFileSnapshot(a: Io.File.Stat, b: Io.File.Stat) bool {
    return a.kind == b.kind and
        a.inode == b.inode and
        a.size == b.size and
        a.mtime.nanoseconds == b.mtime.nanoseconds and
        a.ctime.nanoseconds == b.ctime.nanoseconds;
}

test "find executable in an explicit PATH value" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = executableName("qemu-system-x86_64");
    var executable = try tmp.dir.createFile(io, name, .{ .permissions = .executable_file });
    executable.close(io);

    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const found = (try findExecutableInPathValueAlloc(
        allocator,
        io,
        path_buf[0..path_len],
        "qemu-system-x86_64",
    )).?;
    defer allocator.free(found);
    try std.testing.expectEqualStrings(name, std.fs.path.basename(found));
}

test "qemu executable names cover both guest architectures" {
    try std.testing.expectEqualStrings(
        executableName("qemu-system-x86_64"),
        qemuSystemName(.x86_64),
    );
    try std.testing.expectEqualStrings(
        executableName("qemu-system-aarch64"),
        qemuSystemName(.aarch64),
    );
}

test "find packaged raw x86 firmware in a data directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "share", .default_dir);
    try tmp.dir.writeFile(io, .{
        .sub_path = "share/edk2-x86_64-code.fd",
        .data = "code",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "share/edk2-i386-vars.fd",
        .data = "vars",
    });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const data_dir = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "share" });
    defer allocator.free(data_dir);

    var pair = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .data_dirs = &.{data_dir},
        .include_system_candidates = false,
    })).?;
    defer pair.deinit(allocator);
    try std.testing.expectEqual(FirmwareEncoding.raw, pair.code.encoding);
    try std.testing.expectEqualStrings(
        "edk2-x86_64-code.fd",
        std.fs.path.basename(pair.code.path),
    );
}

test "secure boot firmware search never falls back to ordinary OVMF" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "OVMF_CODE_4M.fd", .data = "ordinary" });
    try tmp.dir.writeFile(io, .{ .sub_path = "OVMF_VARS_4M.fd", .data = "ordinary-vars" });
    const data_dir = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(data_dir);
    try std.testing.expect((try findFirmwareInDataDirAlloc(
        allocator,
        io,
        data_dir,
        .x86_64,
        true,
        .raw,
    )) == null);

    try tmp.dir.writeFile(io, .{
        .sub_path = "OVMF_CODE_4M.secboot.fd",
        .data = "secure",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "OVMF_VARS_4M.ms.fd",
        .data = "microsoft-vars",
    });
    var pair = (try findFirmwareInDataDirAlloc(
        allocator,
        io,
        data_dir,
        .x86_64,
        true,
        .raw,
    )).?;
    defer pair.deinit(allocator);
    try std.testing.expectEqualStrings(
        "OVMF_CODE_4M.secboot.fd",
        std.fs.path.basename(pair.code.path),
    );
}

test "secure boot explicit firmware rejects an ordinary code image" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "OVMF_CODE_4M.fd", .data = "ordinary" });
    try tmp.dir.writeFile(io, .{ .sub_path = "OVMF_VARS_4M.fd", .data = "vars" });
    const code = try tmp.dir.realPathFileAlloc(io, "OVMF_CODE_4M.fd", allocator);
    defer allocator.free(code);
    const vars = try tmp.dir.realPathFileAlloc(io, "OVMF_VARS_4M.fd", allocator);
    defer allocator.free(vars);
    try std.testing.expectError(
        error.FirmwareNotSecureBootCapable,
        findFirmwareSourcePairAlloc(allocator, io, .{
            .secure_boot = true,
            .explicit_code_path = code,
            .explicit_vars_path = vars,
        }),
    );
}

test "find Ubuntu AAVMF regular firmware in a data directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "AAVMF", .default_dir);
    try tmp.dir.writeFile(io, .{
        .sub_path = "AAVMF/AAVMF_CODE.no-secboot.fd",
        .data = "code",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "AAVMF/AAVMF_VARS.fd",
        .data = "vars",
    });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const data_dir = try std.fs.path.join(
        allocator,
        &.{ root_buf[0..root_len], "AAVMF" },
    );
    defer allocator.free(data_dir);

    var pair = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = .aarch64,
        .data_dirs = &.{data_dir},
        .include_system_candidates = false,
    })).?;
    defer pair.deinit(allocator);
    try std.testing.expectEqual(FirmwareEncoding.raw, pair.code.encoding);
    try std.testing.expectEqualStrings(
        "AAVMF_CODE.no-secboot.fd",
        std.fs.path.basename(pair.code.path),
    );
}

test "find packaged AAVMF and pflash firmware in a data directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "aavmf", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "aavmf/AAVMF_CODE.fd", .data = "code" });
    try tmp.dir.writeFile(io, .{ .sub_path = "aavmf/AAVMF_VARS.fd", .data = "vars" });
    try tmp.dir.createDir(io, "pflash", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "pflash/QEMU_EFI-pflash.raw", .data = "code" });
    try tmp.dir.writeFile(io, .{ .sub_path = "pflash/vars-template-pflash.raw", .data = "vars" });

    const aavmf_dir = try tmp.dir.realPathFileAlloc(io, "aavmf", allocator);
    defer allocator.free(aavmf_dir);
    var aavmf = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = .aarch64,
        .data_dirs = &.{aavmf_dir},
        .include_system_candidates = false,
    })).?;
    defer aavmf.deinit(allocator);
    try std.testing.expectEqualStrings("AAVMF_CODE.fd", std.fs.path.basename(aavmf.code.path));

    const pflash_dir = try tmp.dir.realPathFileAlloc(io, "pflash", allocator);
    defer allocator.free(pflash_dir);
    var pflash = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = .aarch64,
        .data_dirs = &.{pflash_dir},
        .include_system_candidates = false,
    })).?;
    defer pflash.deinit(allocator);
    try std.testing.expectEqualStrings(
        "QEMU_EFI-pflash.raw",
        std.fs.path.basename(pflash.code.path),
    );
}

test "compressed firmware is discovered for both architectures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "share", .default_dir);

    for ([_][]const u8{
        "share/edk2-x86_64-code.fd.bz2",
        "share/edk2-i386-vars.fd.bz2",
        "share/edk2-aarch64-code.fd.bz2",
        "share/edk2-arm-vars.fd.bz2",
    }) |path| {
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "compressed" });
    }

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const data_dir = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "share" });
    defer allocator.free(data_dir);

    var x86 = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .data_dirs = &.{data_dir},
        .include_system_candidates = false,
    })).?;
    defer x86.deinit(allocator);
    try std.testing.expectEqual(FirmwareEncoding.bzip2, x86.code.encoding);

    var arm = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = .aarch64,
        .data_dirs = &.{data_dir},
        .include_system_candidates = false,
    })).?;
    defer arm.deinit(allocator);
    try std.testing.expectEqualStrings(
        "edk2-arm-vars.fd.bz2",
        std.fs.path.basename(arm.vars.path),
    );
}

test "raw firmware wins over compressed firmware in an earlier directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "compressed", .default_dir);
    try tmp.dir.createDir(io, "raw", .default_dir);
    try tmp.dir.writeFile(io, .{
        .sub_path = "compressed/edk2-x86_64-code.fd.bz2",
        .data = "compressed-code",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "compressed/edk2-i386-vars.fd.bz2",
        .data = "compressed-vars",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "raw/edk2-x86_64-code.fd",
        .data = "raw-code",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "raw/edk2-i386-vars.fd",
        .data = "raw-vars",
    });

    const compressed = try tmp.dir.realPathFileAlloc(io, "compressed", allocator);
    defer allocator.free(compressed);
    const raw = try tmp.dir.realPathFileAlloc(io, "raw", allocator);
    defer allocator.free(raw);
    var pair = (try findFirmwareSourcePairAlloc(allocator, io, .{
        .data_dirs = &.{ compressed, raw },
        .include_system_candidates = false,
    })).?;
    defer pair.deinit(allocator);
    try std.testing.expectEqual(FirmwareEncoding.raw, pair.code.encoding);
    try std.testing.expectEqualStrings("raw", std.fs.path.basename(
        std.fs.path.dirname(pair.code.path).?,
    ));
}

test "materialize compressed firmware and preserve existing vars" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const compressed_hex = "425a6839314159265359b2fb814a0000031180000223265480200022000f508069a6872f849c1e4e188f177245385090b2fb814a";
    var compressed: [compressed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, compressed_hex);
    try tmp.dir.writeFile(io, .{ .sub_path = "code.bz2", .data = &compressed });
    try tmp.dir.writeFile(io, .{ .sub_path = "vars.bz2", .data = &compressed });

    const code_source = try tmp.dir.realPathFileAlloc(io, "code.bz2", allocator);
    defer allocator.free(code_source);
    const vars_source = try tmp.dir.realPathFileAlloc(io, "vars.bz2", allocator);
    defer allocator.free(vars_source);
    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const code_dest = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "vm.code.fd" });
    defer allocator.free(code_dest);
    const vars_dest = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "vm.vars.fd" });
    defer allocator.free(vars_dest);

    var pair = try materializeFirmwarePairAlloc(
        allocator,
        io,
        .{
            .code = .{ .path = code_source, .encoding = .bzip2 },
            .vars = .{ .path = vars_source, .encoding = .bzip2 },
        },
        code_dest,
        vars_dest,
        .{},
    );
    defer pair.deinit(allocator);
    const code = try Io.Dir.cwd().readFileAlloc(
        io,
        code_dest,
        allocator,
        .limited(64),
    );
    defer allocator.free(code);
    try std.testing.expectEqualStrings("firmware-template", code);

    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = vars_dest,
        .data = "persistent-state",
    });
    var reused = try materializeFirmwarePairAlloc(
        allocator,
        io,
        .{
            .code = .{ .path = code_source, .encoding = .bzip2 },
            .vars = .{ .path = vars_source, .encoding = .bzip2 },
        },
        code_dest,
        vars_dest,
        .{},
    );
    defer reused.deinit(allocator);
    const vars = try Io.Dir.cwd().readFileAlloc(
        io,
        vars_dest,
        allocator,
        .limited(64),
    );
    defer allocator.free(vars);
    try std.testing.expectEqualStrings("persistent-state", vars);
}

test "invalid compressed firmware publishes nothing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "invalid.bz2", .data = "invalid" });

    const source = try tmp.dir.realPathFileAlloc(io, "invalid.bz2", allocator);
    defer allocator.free(source);
    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const destination = try std.fs.path.join(
        allocator,
        &.{ root_buf[0..root_len], "firmware.fd" },
    );
    defer allocator.free(destination);

    try std.testing.expectError(
        error.InvalidBzip2Data,
        materializeFirmwareFile(
            io,
            .{ .path = source, .encoding = .bzip2 },
            destination,
            .{},
        ),
    );
    try std.testing.expect(!try pathAccessible(io, destination, .{ .read = true }));
}

test "firmware materialization reports whether it published the destination" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "source.fd",
        .data = "firmware",
    });

    const source = try tmp.dir.realPathFileAlloc(io, "source.fd", allocator);
    defer allocator.free(source);
    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const destination = try std.fs.path.join(
        allocator,
        &.{ root_buf[0..root_len], "destination.fd" },
    );
    defer allocator.free(destination);

    try std.testing.expect(try materializeFirmwareFileCreated(
        io,
        .{ .path = source, .encoding = .raw },
        destination,
        .{},
    ));
    try std.testing.expect(!try materializeFirmwareFileCreated(
        io,
        .{ .path = source, .encoding = .raw },
        destination,
        .{},
    ));
}

test "truncated and CRC-invalid compressed firmware publish nothing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const compressed_hex = "425a6839314159265359b2fb814a0000031180000223265480200022000f508069a6872f849c1e4e188f177245385090b2fb814a";
    var compressed: [compressed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, compressed_hex);
    try tmp.dir.writeFile(io, .{
        .sub_path = "truncated.bz2",
        .data = compressed[0 .. compressed.len - 2],
    });
    compressed[compressed.len - 1] ^= 0xff;
    try tmp.dir.writeFile(io, .{
        .sub_path = "crc-invalid.bz2",
        .data = &compressed,
    });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const truncated_source = try std.fs.path.join(allocator, &.{ root, "truncated.bz2" });
    defer allocator.free(truncated_source);
    const invalid_source = try std.fs.path.join(allocator, &.{ root, "crc-invalid.bz2" });
    defer allocator.free(invalid_source);
    const truncated_dest = try std.fs.path.join(allocator, &.{ root, "truncated.fd" });
    defer allocator.free(truncated_dest);
    const invalid_dest = try std.fs.path.join(allocator, &.{ root, "crc-invalid.fd" });
    defer allocator.free(invalid_dest);

    try std.testing.expectError(
        error.TruncatedBzip2Data,
        materializeFirmwareFile(
            io,
            .{ .path = truncated_source, .encoding = .bzip2 },
            truncated_dest,
            .{},
        ),
    );
    try std.testing.expectError(
        error.InvalidBzip2Data,
        materializeFirmwareFile(
            io,
            .{ .path = invalid_source, .encoding = .bzip2 },
            invalid_dest,
            .{},
        ),
    );
    try std.testing.expect(!try pathAccessible(io, truncated_dest, .{ .read = true }));
    try std.testing.expect(!try pathAccessible(io, invalid_dest, .{ .read = true }));
}

test "trailing and concatenated compressed firmware publish nothing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const compressed_hex = "425a6839314159265359b2fb814a0000031180000223265480200022000f508069a6872f849c1e4e188f177245385090b2fb814a";
    var compressed: [compressed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, compressed_hex);
    var trailing: [compressed.len + 1]u8 = undefined;
    @memcpy(trailing[0..compressed.len], &compressed);
    trailing[compressed.len] = 0;
    var concatenated: [compressed.len * 2]u8 = undefined;
    @memcpy(concatenated[0..compressed.len], &compressed);
    @memcpy(concatenated[compressed.len..], &compressed);
    try tmp.dir.writeFile(io, .{
        .sub_path = "trailing.bz2",
        .data = &trailing,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "concatenated.bz2",
        .data = &concatenated,
    });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const trailing_source = try std.fs.path.join(allocator, &.{ root, "trailing.bz2" });
    defer allocator.free(trailing_source);
    const concatenated_source = try std.fs.path.join(allocator, &.{ root, "concatenated.bz2" });
    defer allocator.free(concatenated_source);
    const trailing_dest = try std.fs.path.join(allocator, &.{ root, "trailing.fd" });
    defer allocator.free(trailing_dest);
    const concatenated_dest = try std.fs.path.join(allocator, &.{ root, "concatenated.fd" });
    defer allocator.free(concatenated_dest);

    try std.testing.expectError(
        error.TrailingBzip2Data,
        materializeFirmwareFile(
            io,
            .{ .path = trailing_source, .encoding = .bzip2 },
            trailing_dest,
            .{},
        ),
    );
    try std.testing.expectError(
        error.TrailingBzip2Data,
        materializeFirmwareFile(
            io,
            .{ .path = concatenated_source, .encoding = .bzip2 },
            concatenated_dest,
            .{},
        ),
    );
    try std.testing.expect(!try pathAccessible(io, trailing_dest, .{ .read = true }));
    try std.testing.expect(!try pathAccessible(io, concatenated_dest, .{ .read = true }));
}

test "firmware materialization enforces output size limits" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "raw.fd", .data = "firmware" });
    const compressed_hex = "425a6839314159265359b2fb814a0000031180000223265480200022000f508069a6872f849c1e4e188f177245385090b2fb814a";
    var compressed: [compressed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, compressed_hex);
    try tmp.dir.writeFile(io, .{ .sub_path = "compressed.bz2", .data = &compressed });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const raw_source = try std.fs.path.join(allocator, &.{ root, "raw.fd" });
    defer allocator.free(raw_source);
    const compressed_source = try std.fs.path.join(allocator, &.{ root, "compressed.bz2" });
    defer allocator.free(compressed_source);
    const raw_dest = try std.fs.path.join(allocator, &.{ root, "raw-output.fd" });
    defer allocator.free(raw_dest);
    const compressed_dest = try std.fs.path.join(allocator, &.{ root, "compressed-output.fd" });
    defer allocator.free(compressed_dest);

    try std.testing.expectError(
        error.FirmwareTooLarge,
        materializeFirmwareFile(
            io,
            .{ .path = raw_source, .encoding = .raw },
            raw_dest,
            .{ .max_output_size = 4 },
        ),
    );
    try std.testing.expectError(
        error.FirmwareTooLarge,
        materializeFirmwareFile(
            io,
            .{ .path = compressed_source, .encoding = .bzip2 },
            compressed_dest,
            .{ .max_output_size = 4 },
        ),
    );
}

test "compressed firmware drains output after consuming all input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const compressed_hex = "425a6839314159265359dd407d390001018400a0000008200030802a695600b1807177245385090dd407d390";
    var compressed: [compressed_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, compressed_hex);
    try tmp.dir.writeFile(io, .{ .sub_path = "large-output.bz2", .data = &compressed });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const source = try std.fs.path.join(allocator, &.{ root, "large-output.bz2" });
    defer allocator.free(source);
    const destination = try std.fs.path.join(allocator, &.{ root, "large-output.fd" });
    defer allocator.free(destination);

    try materializeFirmwareFile(
        io,
        .{ .path = source, .encoding = .bzip2 },
        destination,
        .{},
    );
    const stat = try Io.Dir.cwd().statFile(io, destination, .{});
    try std.testing.expectEqual(@as(u64, 131072), stat.size);

    const file = try Io.Dir.cwd().openFile(io, destination, .{});
    defer file.close(io);
    var edges: [2]u8 = undefined;
    _ = try file.readPositionalAll(io, edges[0..1], 0);
    _ = try file.readPositionalAll(io, edges[1..2], stat.size - 1);
    try std.testing.expectEqualSlices(u8, "AA", &edges);
}

test "materialize firmware pair fills only missing members" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "code-source.fd", .data = "new-code" });
    try tmp.dir.writeFile(io, .{ .sub_path = "vars-source.fd", .data = "new-vars" });
    try tmp.dir.writeFile(io, .{ .sub_path = "vm.code.fd", .data = "existing-code" });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const code_source = try std.fs.path.join(allocator, &.{ root, "code-source.fd" });
    defer allocator.free(code_source);
    const vars_source = try std.fs.path.join(allocator, &.{ root, "vars-source.fd" });
    defer allocator.free(vars_source);
    const code_dest = try std.fs.path.join(allocator, &.{ root, "vm.code.fd" });
    defer allocator.free(code_dest);
    const vars_dest = try std.fs.path.join(allocator, &.{ root, "vm.vars.fd" });
    defer allocator.free(vars_dest);

    var pair = try materializeFirmwarePairAlloc(
        allocator,
        io,
        .{
            .code = .{ .path = code_source, .encoding = .raw },
            .vars = .{ .path = vars_source, .encoding = .raw },
        },
        code_dest,
        vars_dest,
        .{},
    );
    defer pair.deinit(allocator);

    const code = try Io.Dir.cwd().readFileAlloc(io, code_dest, allocator, .limited(32));
    defer allocator.free(code);
    const vars = try Io.Dir.cwd().readFileAlloc(io, vars_dest, allocator, .limited(32));
    defer allocator.free(vars);
    try std.testing.expectEqualStrings("existing-code", code);
    try std.testing.expectEqualStrings("new-vars", vars);
}

test "invalid existing destination prevents partial pair publication" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "code-source.fd", .data = "code" });
    try tmp.dir.writeFile(io, .{ .sub_path = "vars-source.fd", .data = "vars" });
    try tmp.dir.writeFile(io, .{ .sub_path = "vm.vars.fd", .data = "" });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const code_source = try std.fs.path.join(allocator, &.{ root, "code-source.fd" });
    defer allocator.free(code_source);
    const vars_source = try std.fs.path.join(allocator, &.{ root, "vars-source.fd" });
    defer allocator.free(vars_source);
    const code_dest = try std.fs.path.join(allocator, &.{ root, "vm.code.fd" });
    defer allocator.free(code_dest);
    const vars_dest = try std.fs.path.join(allocator, &.{ root, "vm.vars.fd" });
    defer allocator.free(vars_dest);

    try std.testing.expectError(
        error.FirmwareDestinationEmpty,
        materializeFirmwarePairAlloc(
            allocator,
            io,
            .{
                .code = .{ .path = code_source, .encoding = .raw },
                .vars = .{ .path = vars_source, .encoding = .raw },
            },
            code_dest,
            vars_dest,
            .{},
        ),
    );
    try std.testing.expect(!try pathAccessible(io, code_dest, .{ .read = true }));
}

test "symlink firmware sources are rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "real.fd", .data = "firmware" });
    try tmp.dir.symLink(io, "real.fd", "linked.fd", .{});

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const source = try std.fs.path.join(allocator, &.{ root, "linked.fd" });
    defer allocator.free(source);
    const destination = try std.fs.path.join(allocator, &.{ root, "output.fd" });
    defer allocator.free(destination);

    try std.testing.expectError(
        error.FirmwareSourceNotRegularFile,
        materializeFirmwareFile(
            io,
            .{ .path = source, .encoding = .raw },
            destination,
            .{},
        ),
    );
}

test "concurrent pair materialization publishes one complete bundle" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_bytes = "firmware-source" ** 4096;
    try tmp.dir.writeFile(io, .{ .sub_path = "code-source.fd", .data = source_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "vars-source.fd", .data = source_bytes });

    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    const code_source = try std.fs.path.join(allocator, &.{ root, "code-source.fd" });
    defer allocator.free(code_source);
    const vars_source = try std.fs.path.join(allocator, &.{ root, "vars-source.fd" });
    defer allocator.free(vars_source);
    const code_dest = try std.fs.path.join(allocator, &.{ root, "vm.code.fd" });
    defer allocator.free(code_dest);
    const vars_dest = try std.fs.path.join(allocator, &.{ root, "vm.vars.fd" });
    defer allocator.free(vars_dest);

    const Context = struct {
        io: Io,
        source: FirmwareSourcePair,
        code_dest: []const u8,
        vars_dest: []const u8,
        failure: ?anyerror = null,

        fn run(context: *@This()) void {
            var pair = materializeFirmwarePairAlloc(
                std.heap.page_allocator,
                context.io,
                context.source,
                context.code_dest,
                context.vars_dest,
                .{},
            ) catch |err| {
                context.failure = err;
                return;
            };
            pair.deinit(std.heap.page_allocator);
        }
    };

    var contexts: [8]Context = undefined;
    var threads: [contexts.len]std.Thread = undefined;
    for (&contexts, 0..) |*context, index| {
        context.* = .{
            .io = io,
            .source = .{
                .code = .{ .path = code_source, .encoding = .raw },
                .vars = .{ .path = vars_source, .encoding = .raw },
            },
            .code_dest = code_dest,
            .vars_dest = vars_dest,
        };
        threads[index] = try std.Thread.spawn(.{}, Context.run, .{context});
    }
    for (&threads) |*thread| thread.join();
    for (contexts) |context| try std.testing.expect(context.failure == null);

    const code = try Io.Dir.cwd().readFileAlloc(
        io,
        code_dest,
        allocator,
        .limited(source_bytes.len + 1),
    );
    defer allocator.free(code);
    const vars = try Io.Dir.cwd().readFileAlloc(
        io,
        vars_dest,
        allocator,
        .limited(source_bytes.len + 1),
    );
    defer allocator.free(vars);
    try std.testing.expectEqualStrings(source_bytes, code);
    try std.testing.expectEqualStrings(source_bytes, vars);

    var entries: usize = 0;
    var iterable_dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer iterable_dir.close(io);
    var iterator = iterable_dir.iterate();
    while (try iterator.next(io)) |_| entries += 1;
    try std.testing.expectEqual(@as(usize, 4), entries);
}

test "firmware overrides must be complete" {
    try std.testing.expectError(
        error.IncompleteFirmwareOverride,
        findFirmwareSourcePairAlloc(std.testing.allocator, std.testing.io, .{
            .explicit_code_path = "code.fd",
        }),
    );
}

test "unreadable explicit firmware is rejected" {
    try std.testing.expectError(
        error.FirmwareNotReadable,
        findFirmwareSourcePairAlloc(std.testing.allocator, std.testing.io, .{
            .explicit_code_path = "missing-code.fd",
            .explicit_vars_path = "missing-vars.fd",
        }),
    );
}

test "firmware search returns null when no candidate is readable" {
    const pair = try findFirmwareSourcePairAlloc(
        std.testing.allocator,
        std.testing.io,
        .{
            .data_dirs = &.{"definitely-missing-qemu-data-dir"},
            .include_system_candidates = false,
        },
    );
    try std.testing.expect(pair == null);
}
