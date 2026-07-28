//! Extraction of a direct-kernel boot payload from a staged raw image.
//!
//! The `vm` backend boots the image's own kernel and initramfs rather than the
//! image's boot chain. That keeps the guest at the image's architecture with no
//! firmware, bootloader, or init system in the way, and — decisively, now that
//! software emulation is the CI baseline — removes the overwhelming majority of
//! emulated instructions before the guest agent gets control.
//!
//! Nothing here mutates the image. The kernel and initramfs are copied out, the
//! agent is appended to the copy, and the staged image is left byte-identical,
//! so there is no control-plane residue to remove before publication.

const std = @import("std");
const cpio = @import("cpio.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const mbr = @import("mbr.zig");
const root_tree = @import("root_tree.zig");
const uki = @import("uki.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const max_kernel_bytes: u64 = 128 * 1024 * 1024;
pub const max_initrd_bytes: u64 = 1024 * 1024 * 1024;

/// MBR partition type for an EFI system partition. `mbr.PartitionType` is
/// non-exhaustive and does not name it.
const mbr_efi_system: u8 = 0xEF;

pub const Error = error{
    BootPayloadNotFound,
    AmbiguousBootPayload,
    BootPayloadTooLarge,
    UnsupportedBootLayout,
};

/// A file appended to the extracted initramfs. `path` is a cpio member name and
/// so carries no leading slash; a top-level name keeps `rdinit=/<path>` valid
/// without needing any directory members.
pub const Member = struct {
    path: []const u8,
    bytes: []const u8,
    mode: u32 = 0o100755,
    /// Recorded as the member's mtime, so an identical agent produces an
    /// identical initramfs.
    mtime: u64 = 0,
};

/// Where a payload came from, retained for provenance.
pub const Origin = union(enum) {
    /// `/boot` inside the root filesystem, the layout Azure Linux and most
    /// distributions use.
    boot_directory: struct {
        kernel_path: []const u8,
        initrd_path: []const u8,
    },
    /// A unified kernel image on the EFI system partition.
    unified_kernel: struct {
        esp_path: []const u8,
    },
};

pub const Payload = struct {
    kernel: []u8,
    /// The image's initramfs with the guest agent appended. The kernel unpacks
    /// concatenated cpio archives in order and later members win, so appending
    /// an uncompressed archive to a compressed one both works and takes
    /// precedence, without decompressing anything.
    initrd: []u8,
    kernel_release: ?[]u8,
    origin: Origin,

    pub fn deinit(self: *Payload, allocator: Allocator) void {
        allocator.free(self.kernel);
        allocator.free(self.initrd);
        if (self.kernel_release) |release| allocator.free(release);
        switch (self.origin) {
            .boot_directory => |boot| {
                allocator.free(boot.kernel_path);
                allocator.free(boot.initrd_path);
            },
            .unified_kernel => |unified| allocator.free(unified.esp_path),
        }
        self.* = undefined;
    }
};

pub const Options = struct {
    /// The exclusive raw stage produced by `preserved_image.transactRaw`.
    raw_path: []const u8,
    /// Root partition geometry, already resolved by the transaction.
    root_partition_offset: u64,
    /// Files appended to the initramfs: the guest agent and its control
    /// document. Appending the control document here rather than putting it on
    /// a second disk means the guest needs no filesystem driver to read its
    /// instructions.
    members: []const Member,
    /// Selects among several installed kernels. Extraction fails rather than
    /// guessing when more than one is present and no release is named.
    kernel_release: ?[]const u8 = null,
    max_kernel_bytes: u64 = max_kernel_bytes,
    max_initrd_bytes: u64 = max_initrd_bytes,
};

/// Copies a bootable kernel and initramfs out of the staged image and returns
/// them with the guest agent appended to the initramfs.
pub fn extract(allocator: Allocator, io: Io, options: Options) !Payload {
    if (try extractFromBootDirectory(allocator, io, options)) |payload| {
        return payload;
    }
    if (try extractFromUnifiedKernel(allocator, io, options)) |payload| {
        return payload;
    }
    return error.BootPayloadNotFound;
}

fn extractFromBootDirectory(allocator: Allocator, io: Io, options: Options) !?Payload {
    const file = try Io.Dir.cwd().openFile(io, options.raw_path, .{ .mode = .read_only });
    defer file.close(io);

    var reader = ext4.Reader.open(io, file, allocator, .{
        .offset = options.root_partition_offset,
    }) catch return null;
    defer reader.deinit();

    const entries = reader.listDir(io, allocator, "boot") catch return null;
    defer ext4.freeDirEntries(allocator, entries);

    const selected = try selectKernel(entries, options.kernel_release) orelse return null;
    const initrd_name = selectInitrd(entries, selected.release) orelse return null;

    const kernel_path = try std.fmt.allocPrint(allocator, "boot/{s}", .{selected.name});
    errdefer allocator.free(kernel_path);
    const initrd_path = try std.fmt.allocPrint(allocator, "boot/{s}", .{initrd_name});
    errdefer allocator.free(initrd_path);

    const kernel = try reader.readFileAlloc(io, allocator, kernel_path);
    errdefer allocator.free(kernel);
    if (kernel.len > options.max_kernel_bytes) return error.BootPayloadTooLarge;

    const original_initrd = try reader.readFileAlloc(io, allocator, initrd_path);
    defer allocator.free(original_initrd);
    if (original_initrd.len > options.max_initrd_bytes) return error.BootPayloadTooLarge;

    const initrd = try appendMembers(allocator, original_initrd, options.members);
    errdefer allocator.free(initrd);

    const release = if (selected.release) |value|
        try allocator.dupe(u8, value)
    else
        null;

    return .{
        .kernel = kernel,
        .initrd = initrd,
        .kernel_release = release,
        .origin = .{ .boot_directory = .{
            .kernel_path = kernel_path,
            .initrd_path = initrd_path,
        } },
    };
}

fn extractFromUnifiedKernel(allocator: Allocator, io: Io, options: Options) !?Payload {
    var image = image_mod.Image.openPathReadOnlyStandalone(io, options.raw_path) catch
        return null;
    defer image.close(io);
    const esp = (try findEspRegion(allocator, io, image)) orelse return null;

    var filesystem = fat32.open(&image, io, esp) catch return null;
    const entries = filesystem.listDirAlloc(io, allocator, "EFI/Linux") catch return null;
    defer fat32.freeDirEntries(allocator, entries);

    var chosen: ?[]const u8 = null;
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (!std.ascii.endsWithIgnoreCase(entry.name, ".efi")) continue;
        if (chosen != null) return error.AmbiguousBootPayload;
        chosen = entry.name;
    }
    const name = chosen orelse return null;

    const esp_path = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{name});
    errdefer allocator.free(esp_path);
    const bundle = try filesystem.readFileAlloc(io, allocator, esp_path);
    defer allocator.free(bundle);

    var inspection = uki.inspect(allocator, bundle) catch return error.UnsupportedBootLayout;
    defer inspection.deinit(allocator);

    const linux_section = inspection.findSection(".linux") orelse
        return error.UnsupportedBootLayout;
    const initrd_section = inspection.findSection(".initrd") orelse
        return error.UnsupportedBootLayout;
    if (linux_section.contents.len > options.max_kernel_bytes or
        initrd_section.contents.len > options.max_initrd_bytes)
    {
        return error.BootPayloadTooLarge;
    }

    const kernel = try allocator.dupe(u8, linux_section.contents);
    errdefer allocator.free(kernel);
    const initrd = try appendMembers(allocator, initrd_section.contents, options.members);
    errdefer allocator.free(initrd);

    const release = if (inspection.findSection(".uname")) |uname|
        try allocator.dupe(u8, std.mem.trimEnd(u8, uname.contents, "\x00\n"))
    else
        null;

    return .{
        .kernel = kernel,
        .initrd = initrd,
        .kernel_release = release,
        .origin = .{ .unified_kernel = .{ .esp_path = esp_path } },
    };
}

fn findEspRegion(allocator: Allocator, io: Io, image: image_mod.Image) !?fat32.Region {
    var sector: [mbr.sector_size]u8 = undefined;
    if (try image.pread(io, &sector, 0) != sector.len) return null;
    const boot_record = mbr.Mbr.decode(&sector) catch return null;

    const protective = for (boot_record.entries) |entry| {
        if (entry.partition_type == .gpt_protective) break true;
    } else false;
    if (!protective) {
        for (boot_record.entries) |entry| {
            if (@intFromEnum(entry.partition_type) != mbr_efi_system or
                entry.sector_count == 0) continue;
            return .{
                .offset = @as(u64, entry.first_lba) * mbr.sector_size,
                .length = @as(u64, entry.sector_count) * mbr.sector_size,
            };
        }
        return null;
    }

    const parsed = gpt.readGpt(image, io, allocator) catch return null;
    defer allocator.free(parsed.partitions);
    for (parsed.partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp)) continue;
        const sectors = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
            return null;
        return .{
            .offset = std.math.mul(u64, partition.first_lba, mbr.sector_size) catch return null,
            .length = std.math.mul(u64, sectors, mbr.sector_size) catch return null,
        };
    }
    return null;
}

const SelectedKernel = struct {
    name: []const u8,
    release: ?[]const u8,
};

/// Picks the kernel to boot. Several installed kernels with no named release is
/// an error rather than a guess: booting a different kernel than the one the
/// image would have booted silently changes what is being customized.
fn selectKernel(
    entries: []const ext4.DirEntry,
    requested_release: ?[]const u8,
) Error!?SelectedKernel {
    var selected: ?SelectedKernel = null;
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        const release = kernelRelease(entry.name) orelse continue;
        if (requested_release) |wanted| {
            const actual = release orelse continue;
            if (!std.mem.eql(u8, actual, wanted)) continue;
            return .{ .name = entry.name, .release = actual };
        }
        if (selected != null) return error.AmbiguousBootPayload;
        selected = .{ .name = entry.name, .release = release };
    }
    if (requested_release != null and selected == null) return error.BootPayloadNotFound;
    return selected;
}

/// Returns `null` when the name is not a kernel, and a nested `null` release
/// when it is an unversioned kernel such as `Image` or `vmlinuz`.
fn kernelRelease(name: []const u8) ??[]const u8 {
    const prefixes = [_][]const u8{ "vmlinuz", "vmlinux", "bzImage", "zImage", "Image" };
    for (prefixes) |prefix| {
        if (!std.ascii.startsWithIgnoreCase(name, prefix)) continue;
        const rest = name[prefix.len..];
        if (rest.len == 0) return @as(?[]const u8, null);
        if (rest[0] == '-') return @as(?[]const u8, rest[1..]);
    }
    return null;
}

fn selectInitrd(entries: []const ext4.DirEntry, release: ?[]const u8) ?[]const u8 {
    var fallback: ?[]const u8 = null;
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (!std.ascii.startsWithIgnoreCase(entry.name, "initramfs") and
            !std.ascii.startsWithIgnoreCase(entry.name, "initrd"))
        {
            continue;
        }
        if (release) |wanted| {
            if (std.mem.indexOf(u8, entry.name, wanted) != null) return entry.name;
            continue;
        }
        if (fallback != null) return null;
        fallback = entry.name;
    }
    return fallback;
}

/// Appends an uncompressed cpio archive of `members` to `initrd`.
///
/// The kernel unpacks concatenated initramfs segments in order, sniffing each
/// segment's compression independently, and later members replace earlier ones.
/// So this neither needs to decompress the image's initramfs nor risks losing
/// to a file the image already ships at the same path.
pub fn appendMembers(
    allocator: Allocator,
    initrd: []const u8,
    members: []const Member,
) ![]u8 {
    var out: std.array_list.Managed(u8) = .init(allocator);
    errdefer out.deinit();
    try out.appendSlice(initrd);
    for (members) |member| try writeCpioMember(&out, member);
    try writeCpioTrailer(&out);
    return out.toOwnedSlice();
}

const cpio_header_size = 110;

fn writeCpioMember(out: *std.array_list.Managed(u8), member: Member) !void {
    try writeCpioHeader(out, .{
        .name = member.path,
        .mode = member.mode,
        .size = member.bytes.len,
        .mtime = member.mtime,
        .nlink = 1,
    });
    try out.appendSlice(member.bytes);
    try padTo4(out);
}

fn writeCpioTrailer(out: *std.array_list.Managed(u8)) !void {
    try writeCpioHeader(out, .{
        .name = "TRAILER!!!",
        .mode = 0,
        .size = 0,
        .mtime = 0,
        .nlink = 1,
    });
}

const CpioHeader = struct {
    name: []const u8,
    mode: u32,
    size: usize,
    mtime: u64,
    nlink: u32,
};

fn writeCpioHeader(out: *std.array_list.Managed(u8), header: CpioHeader) !void {
    const start = out.items.len;
    try out.appendSlice(cpio.magic_newc);
    // ino is deliberately constant: the kernel keys hardlinks on it only when
    // nlink > 1, and a constant keeps the archive byte-reproducible.
    try writeHexField(out, 0);
    try writeHexField(out, header.mode);
    try writeHexField(out, 0); // uid: the agent runs as the guest's root
    try writeHexField(out, 0); // gid
    try writeHexField(out, header.nlink);
    try writeHexField(out, @truncate(header.mtime));
    try writeHexField(out, @intCast(header.size));
    try writeHexField(out, 0); // devmajor
    try writeHexField(out, 0); // devminor
    try writeHexField(out, 0); // rdevmajor
    try writeHexField(out, 0); // rdevminor
    try writeHexField(out, @intCast(header.name.len + 1));
    try writeHexField(out, 0); // check, unused by newc
    std.debug.assert(out.items.len - start == cpio_header_size);

    try out.appendSlice(header.name);
    try out.append(0);
    try padTo4(out);
}

fn writeHexField(out: *std.array_list.Managed(u8), value: u32) !void {
    var buffer: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&buffer, "{X:0>8}", .{value}) catch unreachable;
    try out.appendSlice(&buffer);
}

fn padTo4(out: *std.array_list.Managed(u8)) !void {
    while (out.items.len % 4 != 0) try out.append(0);
}

test "the appended agent is a readable cpio member after an existing archive" {
    const allocator = std.testing.allocator;
    var original: std.array_list.Managed(u8) = .init(allocator);
    defer original.deinit();
    try writeCpioMember(&original, .{ .path = "init", .bytes = "original-init" });
    try writeCpioTrailer(&original);

    const combined = try appendMembers(allocator, original.items, &.{
        .{ .path = "zvmi-guest-agent", .bytes = "agent-program" },
        .{ .path = "zvmi-control.json", .bytes = "{}", .mode = 0o100600 },
    });
    defer allocator.free(combined);

    var reader = cpio.Reader.init(combined);
    var names: [4][]const u8 = undefined;
    var count: usize = 0;
    while (try reader.next()) |entry| : (count += 1) {
        if (count == names.len) break;
        names[count] = entry.path;
        if (std.mem.eql(u8, entry.path, "zvmi-guest-agent")) {
            try std.testing.expectEqualStrings("agent-program", entry.content);
            try std.testing.expectEqual(@as(u64, "agent-program".len), entry.size);
        }
        if (std.mem.eql(u8, entry.path, "zvmi-control.json")) {
            try std.testing.expectEqualStrings("{}", entry.content);
        }
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("init", names[0]);
    // The appended members come last, so they replace any same-named file the
    // image already ships.
    try std.testing.expectEqualStrings("zvmi-guest-agent", names[1]);
    try std.testing.expectEqualStrings("zvmi-control.json", names[2]);
}

test "appending an agent leaves the original initramfs bytes untouched" {
    const allocator = std.testing.allocator;
    var original: std.array_list.Managed(u8) = .init(allocator);
    defer original.deinit();
    try writeCpioMember(&original, .{ .path = "init", .bytes = "original-init" });
    try writeCpioTrailer(&original);

    const combined = try appendMembers(allocator, original.items, &.{
        .{ .path = "zvmi-guest-agent", .bytes = "agent" },
    });
    defer allocator.free(combined);
    try std.testing.expectEqualSlices(u8, original.items, combined[0..original.items.len]);
}

test "an identical agent produces an identical archive" {
    const allocator = std.testing.allocator;
    const members = [_]Member{.{ .path = "zvmi-guest-agent", .bytes = "agent" }};
    const first = try appendMembers(allocator, "", &members);
    defer allocator.free(first);
    const second = try appendMembers(allocator, "", &members);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(u8, first, second);
}

test "kernel names are recognized and their release extracted" {
    try std.testing.expect(kernelRelease("System.map-6.12.0") == null);
    try std.testing.expect(kernelRelease("config-6.12.0") == null);
    try std.testing.expect(kernelRelease("initramfs-6.12.0.img") == null);

    try std.testing.expect(kernelRelease("vmlinuz").? == null);
    try std.testing.expect(kernelRelease("Image").? == null);
    try std.testing.expectEqualStrings("6.12.0-1.azl", kernelRelease("vmlinuz-6.12.0-1.azl").?.?);
    try std.testing.expectEqualStrings("6.12.0", kernelRelease("Image-6.12.0").?.?);
}

test "several installed kernels are an error rather than a guess" {
    const two = [_]ext4.DirEntry{
        bootEntry("vmlinuz-6.12.0"),
        bootEntry("vmlinuz-6.13.0"),
        bootEntry("config-6.12.0"),
    };
    try std.testing.expectError(error.AmbiguousBootPayload, selectKernel(&two, null));

    const selected = (try selectKernel(&two, "6.13.0")).?;
    try std.testing.expectEqualStrings("vmlinuz-6.13.0", selected.name);
    try std.testing.expectError(error.BootPayloadNotFound, selectKernel(&two, "6.14.0"));

    const one = [_]ext4.DirEntry{
        bootEntry("vmlinuz-6.12.0"),
        bootEntry("initramfs-6.12.0.img"),
    };
    const only = (try selectKernel(&one, null)).?;
    try std.testing.expectEqualStrings("vmlinuz-6.12.0", only.name);
    try std.testing.expectEqualStrings("6.12.0", only.release.?);
    try std.testing.expectEqualStrings("initramfs-6.12.0.img", selectInitrd(&one, "6.12.0").?);
}

test "an initramfs that does not match the kernel release is not selected" {
    const entries = [_]ext4.DirEntry{
        bootEntry("vmlinuz-6.12.0"),
        bootEntry("initramfs-6.13.0.img"),
    };
    try std.testing.expect(selectInitrd(&entries, "6.12.0") == null);
}

fn bootEntry(name: []const u8) ext4.DirEntry {
    return .{ .inode = 2, .kind = .file, .name = @constCast(name) };
}

test "a kernel and initramfs are extracted from a real ext4 boot directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-boot.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A non-zero offset proves the root partition geometry is honoured rather
    // than the filesystem being assumed to start at byte zero.
    const partition_offset: u64 = 1024 * 1024;
    const partition_length: u64 = 16 * 1024 * 1024;

    var original_initrd: std.array_list.Managed(u8) = .init(allocator);
    defer original_initrd.deinit();
    try writeCpioMember(&original_initrd, .{ .path = "init", .bytes = "distro-init" });
    try writeCpioTrailer(&original_initrd);

    {
        var tree = root_tree.RootTree.initMemory(allocator, io, .{});
        defer tree.deinit();
        try tree.putDirectory("boot", .{ .mode = 0o755 });
        try tree.putFileBytes("boot/vmlinuz-6.12.0-1.azl", "kernel-bytes", .{ .mode = 0o644 });
        try tree.putFileBytes("boot/config-6.12.0-1.azl", "not-a-kernel", .{ .mode = 0o644 });
        try tree.putFileBytes(
            "boot/initramfs-6.12.0-1.azl.img",
            original_initrd.items,
            .{ .mode = 0o600 },
        );

        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        try file.setLength(io, partition_offset + partition_length);
        _ = try ext4.populate(io, file, allocator, try tree.ext4View(), .{
            .offset = partition_offset,
            .length = partition_length,
            .label = "vm-payload",
            .uuid = [_]u8{0x51} ** 16,
            .timestamp = 1_735_689_600,
        });
    }

    var payload = try extract(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = partition_offset,
        .members = &.{.{ .path = "zvmi-guest-agent", .bytes = "agent-program" }},
    });
    defer payload.deinit(allocator);

    try std.testing.expectEqualStrings("kernel-bytes", payload.kernel);
    try std.testing.expectEqualStrings("6.12.0-1.azl", payload.kernel_release.?);
    try std.testing.expectEqualStrings(
        "boot/vmlinuz-6.12.0-1.azl",
        payload.origin.boot_directory.kernel_path,
    );
    try std.testing.expectEqualStrings(
        "boot/initramfs-6.12.0-1.azl.img",
        payload.origin.boot_directory.initrd_path,
    );

    try std.testing.expectEqualSlices(
        u8,
        original_initrd.items,
        payload.initrd[0..original_initrd.items.len],
    );
    var reader = cpio.Reader.init(payload.initrd);
    var found_agent = false;
    while (try reader.next()) |entry| {
        if (!std.mem.eql(u8, entry.path, "zvmi-guest-agent")) continue;
        try std.testing.expectEqualStrings("agent-program", entry.content);
        found_agent = true;
    }
    try std.testing.expect(found_agent);
}

test "extraction fails rather than booting an image with no kernel" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-no-kernel.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    {
        var tree = root_tree.RootTree.initMemory(allocator, io, .{});
        defer tree.deinit();
        try tree.putDirectory("boot", .{ .mode = 0o755 });
        try tree.putFileBytes("boot/config-6.12.0", "not-a-kernel", .{ .mode = 0o644 });

        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        try file.setLength(io, 16 * 1024 * 1024);
        _ = try ext4.populate(io, file, allocator, try tree.ext4View(), .{
            .length = 16 * 1024 * 1024,
            .uuid = [_]u8{0x52} ** 16,
            .timestamp = 1_735_689_600,
        });
    }

    try std.testing.expectError(error.BootPayloadNotFound, extract(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .members = &.{.{ .path = "zvmi-guest-agent", .bytes = "agent" }},
    }));
}

test "a unified kernel image on the ESP is used when the root has no kernel" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-uki.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var original_initrd: std.array_list.Managed(u8) = .init(allocator);
    defer original_initrd.deinit();
    try writeCpioMember(&original_initrd, .{ .path = "init", .bytes = "uki-init" });
    try writeCpioTrailer(&original_initrd);

    const stub = try uki.syntheticStubPe(allocator, 0x8664);
    defer allocator.free(stub);
    const bundle = try uki.generate(allocator, .{
        .stub = stub,
        .linux = "uki-kernel-bytes",
        .initrd = original_initrd.items,
        .cmdline = "root=/dev/vda2",
        .os_release = "ID=zvmi\n",
        .uname = "6.12.0-1.azl",
    });
    defer allocator.free(bundle);

    const total_sectors: u64 = 64 * 1024 * 1024 / mbr.sector_size;
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        file.close(io);
        var image = try image_mod.Image.openPath(io, path);
        defer image.close(io);
        try image.file.setLength(io, total_sectors * mbr.sector_size);
        image.virtual_size = total_sectors * mbr.sector_size;

        const boot_record = mbr.protectiveMbr(total_sectors).encode();
        try image.pwrite(io, &boot_record, 0);

        var placements: [1]gpt.Placement = undefined;
        try gpt.writeGpt(&image, io, [_]u8{0x60} ** 16, &.{.{
            .type_guid = guid.esp,
            .unique_guid = [_]u8{0x61} ** 16,
            .size_sectors = 48 * 1024 * 1024 / mbr.sector_size,
        }}, &placements);

        const region: fat32.Region = .{
            .offset = placements[0].first_lba * mbr.sector_size,
            .length = (placements[0].last_lba - placements[0].first_lba + 1) * mbr.sector_size,
        };
        try fat32.format(&image, io, .{
            .partition_offset = region.offset,
            .partition_len = region.length,
        });
        var filesystem = try fat32.open(&image, io, region);
        try filesystem.createDir(io, "EFI");
        try filesystem.createDir(io, "EFI/Linux");
        try filesystem.writeFile(io, "EFI/Linux/zvmi.efi", bundle);
    }

    // Offset 0 holds a protective MBR, not an ext4 superblock, so the boot
    // directory probe must decline rather than misread it.
    var payload = try extract(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .members = &.{.{ .path = "zvmi-guest-agent", .bytes = "agent-program" }},
    });
    defer payload.deinit(allocator);

    try std.testing.expectEqualStrings("uki-kernel-bytes", payload.kernel);
    try std.testing.expectEqualStrings("6.12.0-1.azl", payload.kernel_release.?);
    try std.testing.expectEqualStrings("EFI/Linux/zvmi.efi", payload.origin.unified_kernel.esp_path);
    try std.testing.expectEqualSlices(
        u8,
        original_initrd.items,
        payload.initrd[0..original_initrd.items.len],
    );

    var reader = cpio.Reader.init(payload.initrd);
    var found_agent = false;
    while (try reader.next()) |entry| {
        if (std.mem.eql(u8, entry.path, "zvmi-guest-agent")) found_agent = true;
    }
    try std.testing.expect(found_agent);
}
