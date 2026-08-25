const std = @import("std");
const builtin = @import("builtin");
const miz = @import("miz");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const source_size: u64 = 16 * 1024 * 1024;
const grown_size: u64 = 128 * 1024 * 1024;
const command_output_limit: usize = 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping device-write integration: Linux is required\n", .{});
        return;
    }

    const privileged_child = argv.len == 3 and
        std.mem.eql(u8, argv[1], "--privileged");
    const explicitly_requested = if (init.environ_map.get(
        "MIZ_RUN_PRIVILEGED_TEST",
    )) |value|
        std.mem.eql(u8, value, "1")
    else
        false;
    if (!explicitly_requested and !privileged_child) {
        std.debug.print(
            "skipping device-write integration: set MIZ_RUN_PRIVILEGED_TEST=1 to opt in\n",
            .{},
        );
        return;
    }

    const miz_path = if (privileged_child)
        argv[2]
    else if (argv.len == 2)
        argv[1]
    else
        return error.MissingMizExecutable;
    if (std.os.linux.geteuid() != 0) {
        return reexecWithSudo(init.io, argv[0], miz_path);
    }
    try runIntegration(allocator, init.io, miz_path);
}

fn reexecWithSudo(io: Io, self_exe: []const u8, miz_path: []const u8) !void {
    const sudo = if (isExecutable(io, "/usr/bin/sudo"))
        "/usr/bin/sudo"
    else if (isExecutable(io, "/bin/sudo"))
        "/bin/sudo"
    else
        return error.SudoUnavailable;
    var child = try std.process.spawn(io, .{
        .argv = &.{ sudo, "-n", self_exe, "--privileged", miz_path },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.PrivilegedTestFailed,
        else => return error.PrivilegedTestFailed,
    }
}

fn runIntegration(
    allocator: Allocator,
    io: Io,
    miz_path: []const u8,
) !void {
    const losetup = findLosetup(io) orelse return error.LosetupUnavailable;

    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const work_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/miz-device-write-integration-{s}",
        .{&random_hex},
    );
    try Io.Dir.cwd().createDir(io, work_path, .default_dir);
    var completed = false;
    defer if (!completed) {
        std.debug.print(
            "device-write integration retained failed workspace: {s}\n",
            .{work_path},
        );
    };

    const source_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "source.raw" },
    );
    try createGptSource(io, source_path);
    const source_digest = try digestOfFile(io, source_path);

    var source_image = try miz.Image.openPathReadOnly(io, source_path);
    defer source_image.close(io);
    var source_gpt = try miz.gpt.readVerifiedGpt(
        source_image,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer source_gpt.deinit(allocator);

    const cases = [_]struct {
        name: []const u8,
        target_size: u64,
        relocated: bool,
    }{
        .{ .name = "grown", .target_size = grown_size, .relocated = true },
        .{ .name = "same", .target_size = source_size, .relocated = false },
    };
    for (cases) |case| {
        const backing_path = try std.fmt.allocPrint(
            allocator,
            "{s}/destination-{s}.raw",
            .{ work_path, case.name },
        );
        {
            var backing = try miz.Image.create(
                io,
                backing_path,
                .raw,
                case.target_size,
                .{},
            );
            backing.close(io);
        }

        var loop = try LoopDevice.attach(
            allocator,
            io,
            losetup,
            backing_path,
        );
        defer loop.deinit(io);

        const write_output = try runSuccessful(
            allocator,
            io,
            &.{
                miz_path,
                "write",
                "--allow-device-write",
                "--yes",
                source_path,
                loop.path,
            },
        );
        defer write_output.deinit(allocator);
        if (case.relocated) {
            try require(
                std.mem.indexOf(
                    u8,
                    write_output.stderr,
                    "write: backup GPT LBA ",
                ) != null and
                    std.mem.indexOf(
                        u8,
                        write_output.stderr,
                        "(already at destination end)",
                    ) == null,
                "grown write did not report a GPT relocation",
            );
        } else {
            try require(
                std.mem.indexOf(
                    u8,
                    write_output.stderr,
                    "(already at destination end)",
                ) != null,
                "same-size write did not report the no-op relocation",
            );
        }

        {
            var destination = try miz.Image.openPathReadOnly(io, loop.path);
            defer destination.close(io);
            try require(
                destination.virtual_size == case.target_size,
                "loop-device size did not match its sparse backing file",
            );
            try require(
                destination.device.?.geometry.logical_sector_size ==
                    miz.gpt.sector_size,
                "loop device did not expose 512-byte logical sectors",
            );

            var destination_gpt = try miz.gpt.readVerifiedGpt(
                destination,
                io,
                allocator,
                miz.gpt.default_max_partition_array_bytes,
            );
            defer destination_gpt.deinit(allocator);

            const total_sectors = case.target_size / miz.gpt.sector_size;
            const backup_lba = total_sectors - 1;
            const array_sectors = try std.math.divCeil(
                u64,
                @intCast(destination_gpt.partition_array.len),
                miz.gpt.sector_size,
            );
            const last_usable_lba = backup_lba - array_sectors - 1;
            try require(
                destination_gpt.primary_header.backup_lba == backup_lba,
                "primary GPT AlternateLBA did not reach the destination end",
            );
            try require(
                destination_gpt.backup_header.current_lba == backup_lba,
                "backup GPT header was not stored at the destination end",
            );
            try require(
                destination_gpt.primary_header.last_usable_lba ==
                    last_usable_lba and
                    destination_gpt.backup_header.last_usable_lba ==
                        last_usable_lba,
                "GPT last usable LBA did not reflect the destination size",
            );
            try require(
                std.mem.eql(
                    u8,
                    &source_gpt.primary_header.disk_guid,
                    &destination_gpt.primary_header.disk_guid,
                ),
                "disk GUID changed during device write",
            );
            try require(
                std.mem.eql(
                    u8,
                    source_gpt.partition_array,
                    destination_gpt.partition_array,
                ),
                "opaque GPT partition array changed during device write",
            );
            try require(
                source_gpt.partitions.len == destination_gpt.partitions.len,
                "partition count changed during device write",
            );
            for (
                source_gpt.partitions,
                destination_gpt.partitions,
            ) |source_partition, destination_partition| {
                try require(
                    std.mem.eql(
                        u8,
                        &source_partition.partition_type_guid,
                        &destination_partition.partition_type_guid,
                    ) and
                        std.mem.eql(
                            u8,
                            &source_partition.unique_partition_guid,
                            &destination_partition.unique_partition_guid,
                        ) and
                        std.mem.eql(
                            u8,
                            std.mem.asBytes(&source_partition.name_utf16le),
                            std.mem.asBytes(&destination_partition.name_utf16le),
                        ),
                    "partition GUID or name changed during device write",
                );
            }

            // A grown protective MBR must advertise the destination span;
            // every source byte outside that canonical table tail is retained.
            var expected_mbr = source_gpt.protective_mbr_sector;
            const resized_mbr = miz.mbr.protectiveMbr(total_sectors);
            resized_mbr.encodePartitionTableInto(&expected_mbr);
            try require(
                std.mem.eql(
                    u8,
                    &expected_mbr,
                    &destination_gpt.protective_mbr_sector,
                ),
                "protective MBR changed outside its destination geometry",
            );
            try require(
                destination_gpt.protective_mbr_sector[17] == 0xa5,
                "protective MBR bootstrap bytes were not preserved",
            );
        }

        try loop.detach(io);
        if (!case.relocated) {
            try require(
                std.mem.eql(
                    u8,
                    &source_digest,
                    &(try digestOfFile(io, backing_path)),
                ),
                "same-size write changed source image bytes",
            );
        }
    }

    try Io.Dir.cwd().deleteTree(io, work_path);
    completed = true;
    std.debug.print("device-write integration passed\n", .{});
}

fn createGptSource(io: Io, path: []const u8) !void {
    var image = try miz.Image.create(io, path, .raw, source_size, .{});
    defer image.close(io);
    const specs = [_]miz.gpt.PartitionSpec{
        .{
            .type_guid = miz.guid.esp,
            .unique_guid = miz.guid.parse(
                "11111111-2222-3333-4444-555555555555",
            ),
            .size_sectors = 4096,
            .name_utf16le = miz.gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = miz.guid.linux_filesystem_data,
            .unique_guid = miz.guid.parse(
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ),
            .size_sectors = 8192,
            .name_utf16le = miz.gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]miz.gpt.Placement = undefined;
    try miz.gpt.writeGpt(
        &image,
        io,
        miz.guid.parse("99999999-8888-7777-6666-555555555555"),
        &specs,
        &placements,
    );

    var protective_mbr: [miz.mbr.sector_size]u8 = undefined;
    try require(
        try image.pread(io, &protective_mbr, 0) == protective_mbr.len,
        "could not read the source protective MBR",
    );
    protective_mbr[17] = 0xa5;
    try image.pwrite(io, &protective_mbr, 0);
}

const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: CommandOutput, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

fn runSuccessful(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
) !CommandOutput {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(command_output_limit),
        .stderr_limit = .limited(command_output_limit),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(90),
            .clock = .awake,
        } },
    });
    switch (result.term) {
        .exited => |code| if (code == 0) {
            return .{ .stdout = result.stdout, .stderr = result.stderr };
        },
        else => {},
    }
    std.debug.print(
        "command failed: {s}\nstdout:\n{s}\nstderr:\n{s}\n",
        .{ argv[0], result.stdout, result.stderr },
    );
    allocator.free(result.stdout);
    allocator.free(result.stderr);
    return error.CommandFailed;
}

const LoopDevice = struct {
    allocator: Allocator,
    losetup: []const u8,
    path: []u8,
    attached: bool = true,

    fn attach(
        allocator: Allocator,
        io: Io,
        losetup: []const u8,
        backing_path: []const u8,
    ) !LoopDevice {
        const output = try runSuccessful(
            allocator,
            io,
            &.{ losetup, "--find", "--show", "--partscan", backing_path },
        );
        defer output.deinit(allocator);
        const path = std.mem.trim(u8, output.stdout, " \t\r\n");
        try require(
            validLoopPath(path),
            "losetup returned an invalid loop-device path",
        );
        return .{
            .allocator = allocator,
            .losetup = losetup,
            .path = try allocator.dupe(u8, path),
        };
    }

    fn detach(self: *LoopDevice, io: Io) !void {
        if (!self.attached) return;
        const output = try runSuccessful(
            self.allocator,
            io,
            &.{ self.losetup, "--detach", self.path },
        );
        output.deinit(self.allocator);
        self.attached = false;
    }

    fn deinit(self: *LoopDevice, io: Io) void {
        if (self.attached) {
            self.detach(io) catch |err| {
                std.debug.print(
                    "failed to detach loop device '{s}': {s}\n",
                    .{ self.path, @errorName(err) },
                );
            };
        }
        self.allocator.free(self.path);
    }
};

fn validLoopPath(path: []const u8) bool {
    const prefix = "/dev/loop";
    if (!std.mem.startsWith(u8, path, prefix) or path.len == prefix.len) {
        return false;
    }
    for (path[prefix.len..]) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn findLosetup(io: Io) ?[]const u8 {
    for ([_][]const u8{
        "/usr/sbin/losetup",
        "/sbin/losetup",
        "/usr/bin/losetup",
    }) |path| {
        if (isExecutable(io, path)) return path;
    }
    return null;
}

fn isExecutable(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{ .execute = true }) catch return false;
    return true;
}

fn digestOfFile(io: Io, path: []const u8) ![32]u8 {
    var buffer: [64 * 1024]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var offset: u64 = 0;
    while (true) {
        const read = try file.readPositionalAll(io, &buffer, offset);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        offset += read;
        if (read < buffer.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn require(condition: bool, comptime message: []const u8) !void {
    if (condition) return;
    std.debug.print("device-write integration assertion failed: {s}\n", .{message});
    return error.IntegrationAssertionFailed;
}
