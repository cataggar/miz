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
const kernel_modules = @import("kernel_modules.zig");
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
    GuestDriversUndetermined,
    NoDiskDriver,
    NoRootFilesystemDriver,
    NoNetworkDriver,
    NoVirtioBusDriver,
    ModuleFileUnreadable,
    ModulePayloadTooLarge,
};

/// How the guest's disks are attached.
///
/// The agent runs as `rdinit`, so the only drivers the guest has are the ones
/// its kernel built in and the ones the agent inserts from the image's own
/// module tree. Either way the answer is read out of the image rather than
/// assumed: Azure Linux builds `virtio_scsi` in and ships `virtio_blk` as a
/// compressed module, while Debian's cloud kernels modularize both.
pub const DiskTransport = enum {
    /// `virtio-blk`, exposed as `/dev/vd*`.
    virtio_blk,
    /// `virtio-scsi`, exposed as `/dev/sd*` in the order the drives are
    /// attached.
    virtio_scsi,

    /// The device path for the `index`th disk attached over this transport.
    pub fn devicePath(self: DiskTransport, buffer: []u8, index: u8) []const u8 {
        const prefix = switch (self) {
            .virtio_blk => "/dev/vd",
            .virtio_scsi => "/dev/sd",
        };
        return std.fmt.bufPrint(buffer, "{s}{c}", .{ prefix, 'a' + index }) catch
            unreachable;
    }
};

/// What the guest will be able to drive, and what it takes to get there.
pub const GuestDrivers = struct {
    disk: DiskTransport,
    /// Whether the guest will have a network driver. Only consulted when the
    /// plan declares repositories, since an offline guest is given no network
    /// device at all.
    network: bool,
    /// Modules to insert, in insertion order, before the guest waits for its
    /// disks or mounts the target. Empty when the image's kernel builds in
    /// everything the run needs, which is the case this backend started with
    /// and the case that stays byte for byte unchanged.
    modules: []const Module,

    pub fn deinit(self: *GuestDrivers, allocator: Allocator) void {
        for (self.modules) |module| module.deinit(allocator);
        allocator.free(self.modules);
        self.* = undefined;
    }
};

/// A module read out of the image's own tree, decompressed on the host and
/// ready to be appended to the initramfs beside the agent.
pub const Module = struct {
    /// The name the kernel knows it by, e.g. `ext4`.
    name: []const u8,
    /// Where it came from inside the image, so provenance can name the file
    /// that was loaded rather than only the driver it provides.
    image_path: []const u8,
    /// The initramfs member it is appended as, which is also what the control
    /// document names. Numbered so the agent's insertion order is the
    /// dependency order the host resolved.
    member_path: []const u8,
    bytes: []const u8,
    sha256: [32]u8,

    fn deinit(self: Module, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.image_path);
        allocator.free(self.member_path);
        allocator.free(self.bytes);
    }
};

/// The filesystem the guest agent mounts the target root with. It is fixed
/// rather than probed because the agent issues exactly this mount.
pub const root_filesystem_module = "ext4";

/// The bus every device this backend attaches sits on. Both machine types the
/// backend uses — `q35` and `virt` — are PCI, so a kernel that can drive
/// neither a built-in nor a loadable `virtio_pci` sees no virtio device at all.
const virtio_bus_module = "virtio_pci";

/// SCSI disks appear as `/dev/sd*` only once the SCSI disk driver is there.
/// `modules.dep` does not record it as a dependency of `virtio_scsi`, because
/// it is not one: it is a separate driver that the same disk needs.
const scsi_disk_module = "sd_mod";

const network_module = "virtio_net";

/// `modules.dep` records symbol dependencies, and ext4 has none on a checksum
/// driver: it asks the crypto API for "crc32c" by name while it mounts, and a
/// guest with no module loader gets no second chance — the mount fails with
/// "Cannot load crc32c driver" after every driver it does list loaded.
///
/// The first name that exists wins, and none existing is not a refusal:
/// kernels from 6.14 on call the crc32c library directly and ship no crypto
/// module under any of these names, so an absent provider there means an
/// image that needs none.
const checksum_modules = [_][]const u8{ "crc32c_generic", "crc32c" };

/// Bounds on what may be appended to the initramfs. The `ext4` closure is on
/// the order of a megabyte, so these are ceilings on a malformed tree rather
/// than limits a real image approaches.
pub const max_modules: usize = 64;
pub const max_module_payload_bytes: usize = 64 * 1024 * 1024;

/// Reads the image's module tree and reports what the guest will be able to
/// see, with the modules that have to be inserted to make that true.
///
/// A guess here is not a wrong answer that shows up as a wrong answer: it is a
/// root device that never appears, which the guest can only report as a
/// timeout. So this fails rather than guesses, and the caller refuses the run
/// before anything boots.
pub fn probeDrivers(
    allocator: Allocator,
    io: Io,
    options: ProbeOptions,
) !GuestDrivers {
    const file = try Io.Dir.cwd().openFile(io, options.raw_path, .{ .mode = .read_only });
    defer file.close(io);

    var reader = ext4.Reader.open(io, file, allocator, .{
        .offset = options.root_partition_offset,
    }) catch return error.GuestDriversUndetermined;
    defer reader.deinit();

    const release = try resolveModuleRelease(allocator, io, &reader, options.kernel_release);
    defer allocator.free(release);

    const tree_path = try std.fmt.allocPrint(allocator, "lib/modules/{s}", .{release});
    defer allocator.free(tree_path);

    const builtin_listing = readTreeFile(allocator, io, &reader, tree_path, "modules.builtin") catch
        return error.GuestDriversUndetermined;
    defer allocator.free(builtin_listing);

    // An image with no `modules.dep` offers nothing to load, which is a
    // narrower image rather than an unreadable one: a kernel that builds every
    // driver in still boots here.
    const dep_bytes = readTreeFile(allocator, io, &reader, tree_path, "modules.dep") catch
        try allocator.dupe(u8, "");
    defer allocator.free(dep_bytes);

    const dependencies = try kernel_modules.Dependencies.parse(allocator, dep_bytes);
    defer dependencies.deinit(allocator);

    var wanted: std.array_list.Managed([]const u8) = .init(allocator);
    defer wanted.deinit();

    // The bus first, then the disk, then the filesystem, then the network:
    // the order modules are named in is the order they are inserted in, and
    // each of these is useless before the one above it.
    switch (availability(builtin_listing, dependencies, virtio_bus_module)) {
        .built_in => {},
        .loadable => try wanted.append(virtio_bus_module),
        .missing => return error.NoVirtioBusDriver,
    }

    const disk = try selectTransport(builtin_listing, dependencies, &wanted);

    switch (availability(builtin_listing, dependencies, root_filesystem_module)) {
        .built_in => {},
        .loadable => try wanted.append(root_filesystem_module),
        .missing => return error.NoRootFilesystemDriver,
    }

    for (checksum_modules) |name| {
        switch (availability(builtin_listing, dependencies, name)) {
            .built_in => break,
            .loadable => {
                try wanted.append(name);
                break;
            },
            .missing => {},
        }
    }

    const network = switch (availability(builtin_listing, dependencies, network_module)) {
        .built_in => true,
        .loadable => blk: {
            // Loaded only for a run that has somewhere to go: an offline guest
            // is given no network device, and inserting a driver for a device
            // that is not there is work that can only fail.
            if (options.network_required) try wanted.append(network_module);
            break :blk true;
        },
        .missing => if (options.network_required) return error.NoNetworkDriver else false,
    };

    return .{
        .disk = disk,
        .network = network,
        .modules = try readModules(allocator, io, &reader, .{
            .tree_path = tree_path,
            .dependencies = dependencies,
            .builtin_listing = builtin_listing,
            .wanted = wanted.items,
        }),
    };
}

pub const ProbeOptions = struct {
    raw_path: []const u8,
    root_partition_offset: u64,
    /// The release whose module tree is consulted. When absent the image must
    /// carry exactly one, for the same reason kernel selection is unambiguous
    /// or an error.
    kernel_release: ?[]const u8 = null,
    /// Whether the run needs the guest to reach a network. Asked here because
    /// it decides whether a modular network driver is worth inserting and
    /// whether its absence is a refusal.
    network_required: bool = false,
};

/// Whether a driver is already in the kernel, available to insert, or absent.
const Availability = enum { built_in, loadable, missing };

fn availability(
    builtin_listing: []const u8,
    dependencies: kernel_modules.Dependencies,
    name: []const u8,
) Availability {
    if (kernel_modules.isBuiltIn(builtin_listing, name)) return .built_in;
    return if (dependencies.indexOfName(name) != null) .loadable else .missing;
}

/// Picks how the guest's disks are attached, and names the modules that
/// choice needs.
///
/// A built-in driver is never traded for a loadable one: a driver that is
/// already in the kernel cannot fail to insert, so preferring it keeps the
/// runs that work today working exactly as they did.
fn selectTransport(
    builtin_listing: []const u8,
    dependencies: kernel_modules.Dependencies,
    wanted: *std.array_list.Managed([]const u8),
) !DiskTransport {
    const block = availability(builtin_listing, dependencies, "virtio_blk");
    const scsi = availability(builtin_listing, dependencies, "virtio_scsi");
    const scsi_disk = availability(builtin_listing, dependencies, scsi_disk_module);

    if (block == .built_in) return .virtio_blk;
    if (scsi == .built_in and scsi_disk != .missing) {
        if (scsi_disk == .loadable) try wanted.append(scsi_disk_module);
        return .virtio_scsi;
    }
    if (block == .loadable) {
        try wanted.append("virtio_blk");
        return .virtio_blk;
    }
    if (scsi == .loadable and scsi_disk != .missing) {
        try wanted.append("virtio_scsi");
        if (scsi_disk == .loadable) try wanted.append(scsi_disk_module);
        return .virtio_scsi;
    }
    return error.NoDiskDriver;
}

const ReadModulesOptions = struct {
    tree_path: []const u8,
    dependencies: kernel_modules.Dependencies,
    builtin_listing: []const u8,
    wanted: []const []const u8,
};

/// Resolves the dependency closure and reads every module in it out of the
/// image, decompressed and digested.
///
/// Everything that can refuse the run happens here, before a kernel is copied
/// or an emulator is started: a module the tree describes but does not hold, a
/// compression format the host cannot read, and a payload larger than the
/// initramfs should carry are all answers the host can give without booting.
fn readModules(
    allocator: Allocator,
    io: Io,
    reader: *ext4.Reader,
    options: ReadModulesOptions,
) ![]const Module {
    const order = try options.dependencies.resolve(
        allocator,
        options.builtin_listing,
        options.wanted,
    );
    defer allocator.free(order);
    if (order.len > max_modules) return error.ModulePayloadTooLarge;

    const modules = try allocator.alloc(Module, order.len);
    var filled: usize = 0;
    errdefer {
        for (modules[0..filled]) |module| module.deinit(allocator);
        allocator.free(modules);
    }

    var total: usize = 0;
    for (order, 0..) |path, index| {
        const image_path = try std.fs.path.join(allocator, &.{ options.tree_path, path });
        errdefer allocator.free(image_path);

        const stored = reader.readFileAlloc(io, allocator, image_path) catch
            return error.ModuleFileUnreadable;
        defer allocator.free(stored);

        const bytes = try kernel_modules.moduleImage(
            allocator,
            path,
            stored,
            kernel_modules.max_module_bytes,
        );
        errdefer allocator.free(bytes);
        total += bytes.len;
        if (total > max_module_payload_bytes) return error.ModulePayloadTooLarge;

        const name = try allocator.dupe(u8, kernel_modules.moduleName(path));
        errdefer allocator.free(name);
        if (!validModuleName(name)) return error.ModuleFileUnreadable;
        const member_path = try std.fmt.allocPrint(
            allocator,
            "miz-module-{d:0>2}-{s}.ko",
            .{ index, name },
        );
        errdefer allocator.free(member_path);

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        modules[filled] = .{
            .name = name,
            .image_path = image_path,
            .member_path = member_path,
            .bytes = bytes,
            .sha256 = digest,
        };
        filled += 1;
    }
    return modules;
}

/// The name comes out of the image, and it becomes both an initramfs member
/// name and a string in the control document, so it is checked rather than
/// trusted.
fn validModuleName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (byte == '_' or byte == '-') continue;
        return false;
    }
    return true;
}

fn readTreeFile(
    allocator: Allocator,
    io: Io,
    reader: *ext4.Reader,
    tree_path: []const u8,
    name: []const u8,
) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ tree_path, name });
    defer allocator.free(path);
    return reader.readFileAlloc(io, allocator, path);
}

fn resolveModuleRelease(
    allocator: Allocator,
    io: Io,
    reader: *ext4.Reader,
    requested: ?[]const u8,
) ![]u8 {
    if (requested) |release| return allocator.dupe(u8, release);
    const entries = reader.listDir(io, allocator, "lib/modules") catch
        return error.GuestDriversUndetermined;
    defer ext4.freeDirEntries(allocator, entries);
    var found: ?[]const u8 = null;
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or
            std.mem.eql(u8, entry.name, ".."))
        {
            continue;
        }
        if (found != null) return error.GuestDriversUndetermined;
        found = entry.name;
    }
    return allocator.dupe(u8, found orelse return error.GuestDriversUndetermined);
}

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
    var writer = cpio.Writer.init(&out, .newc);
    for (members) |member| try writer.append(try cpioMember(member));
    try writer.finish();
    return out.toOwnedSlice();
}

fn cpioMember(member: Member) !cpio.WriteEntry {
    const mtime = std.math.cast(u32, member.mtime) orelse
        return error.InvalidCpioMemberMetadata;
    return .{
        .path = member.path,
        .content = member.bytes,
        .metadata = .{
            // A single link makes this an independent initramfs member.  The
            // remaining zero metadata is deliberate and reproducible.
            .mode = member.mode,
            .mtime = mtime,
        },
    };
}

fn writeCpioMember(out: *std.array_list.Managed(u8), member: Member) !void {
    var writer = cpio.Writer.init(out, .newc);
    try writer.append(try cpioMember(member));
}

fn writeCpioTrailer(out: *std.array_list.Managed(u8)) !void {
    var writer = cpio.Writer.init(out, .newc);
    try writer.finish();
}

test "the appended agent is a readable cpio member after an existing archive" {
    const allocator = std.testing.allocator;
    var original: std.array_list.Managed(u8) = .init(allocator);
    defer original.deinit();
    try writeCpioMember(&original, .{ .path = "init", .bytes = "original-init" });
    try writeCpioTrailer(&original);

    const combined = try appendMembers(allocator, original.items, &.{
        .{ .path = "miz-guest-agent", .bytes = "agent-program" },
        .{ .path = "miz-control.json", .bytes = "{}", .mode = 0o100600 },
    });
    defer allocator.free(combined);

    var reader = cpio.Reader.init(combined);
    var names: [4][]const u8 = undefined;
    var count: usize = 0;
    while (try reader.next()) |entry| : (count += 1) {
        if (count == names.len) break;
        names[count] = entry.path;
        if (std.mem.eql(u8, entry.path, "miz-guest-agent")) {
            try std.testing.expectEqualStrings("agent-program", entry.content);
            try std.testing.expectEqual(@as(u64, "agent-program".len), entry.size);
        }
        if (std.mem.eql(u8, entry.path, "miz-control.json")) {
            try std.testing.expectEqualStrings("{}", entry.content);
        }
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("init", names[0]);
    // The appended members come last, so they replace any same-named file the
    // image already ships.
    try std.testing.expectEqualStrings("miz-guest-agent", names[1]);
    try std.testing.expectEqualStrings("miz-control.json", names[2]);
}

test "appending an agent leaves the original initramfs bytes untouched" {
    const allocator = std.testing.allocator;
    var original: std.array_list.Managed(u8) = .init(allocator);
    defer original.deinit();
    try writeCpioMember(&original, .{ .path = "init", .bytes = "original-init" });
    try writeCpioTrailer(&original);

    const combined = try appendMembers(allocator, original.items, &.{
        .{ .path = "miz-guest-agent", .bytes = "agent" },
    });
    defer allocator.free(combined);
    try std.testing.expectEqualSlices(u8, original.items, combined[0..original.items.len]);
}

test "an identical agent produces an identical archive" {
    const allocator = std.testing.allocator;
    const members = [_]Member{.{ .path = "miz-guest-agent", .bytes = "agent" }};
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
        .members = &.{.{ .path = "miz-guest-agent", .bytes = "agent-program" }},
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
        if (!std.mem.eql(u8, entry.path, "miz-guest-agent")) continue;
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
        .members = &.{.{ .path = "miz-guest-agent", .bytes = "agent" }},
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
        .os_release = "ID=miz\n",
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
        try filesystem.writeFile(io, "EFI/Linux/miz.efi", bundle);
    }

    // Offset 0 holds a protective MBR, not an ext4 superblock, so the boot
    // directory probe must decline rather than misread it.
    var payload = try extract(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .members = &.{.{ .path = "miz-guest-agent", .bytes = "agent-program" }},
    });
    defer payload.deinit(allocator);

    try std.testing.expectEqualStrings("uki-kernel-bytes", payload.kernel);
    try std.testing.expectEqualStrings("6.12.0-1.azl", payload.kernel_release.?);
    try std.testing.expectEqualStrings("EFI/Linux/miz.efi", payload.origin.unified_kernel.esp_path);
    try std.testing.expectEqualSlices(
        u8,
        original_initrd.items,
        payload.initrd[0..original_initrd.items.len],
    );

    var reader = cpio.Reader.init(payload.initrd);
    var found_agent = false;
    while (try reader.next()) |entry| {
        if (std.mem.eql(u8, entry.path, "miz-guest-agent")) found_agent = true;
    }
    try std.testing.expect(found_agent);
}

/// A real Azure Linux `modules.builtin`, trimmed to the drivers this backend
/// asks about: `ext4`, the PCI bus, SCSI and the network are built in, and
/// `virtio_blk` is shipped as `virtio_blk.ko.xz` under the same tree.
const azure_linux_builtin =
    \\kernel/fs/ext4/ext4.ko
    \\kernel/drivers/virtio/virtio.ko
    \\kernel/drivers/virtio/virtio_pci.ko
    \\kernel/drivers/scsi/scsi_mod.ko
    \\kernel/drivers/scsi/sd_mod.ko
    \\kernel/drivers/scsi/virtio_scsi.ko
    \\kernel/drivers/net/virtio_net.ko
    \\
;

/// A kernel that modularizes everything: the shape Debian's cloud kernels
/// have, and the shape this backend used to refuse outright.
const modular_dep =
    \\kernel/drivers/virtio/virtio_pci.ko:
    \\kernel/drivers/block/virtio_blk.ko:
    \\kernel/drivers/scsi/scsi_mod.ko:
    \\kernel/drivers/scsi/sd_mod.ko: kernel/drivers/scsi/scsi_mod.ko
    \\kernel/drivers/scsi/virtio_scsi.ko: kernel/drivers/scsi/scsi_mod.ko
    \\kernel/fs/mbcache.ko:
    \\kernel/fs/jbd2/jbd2.ko:
    \\kernel/fs/ext4/ext4.ko: kernel/fs/mbcache.ko kernel/fs/jbd2/jbd2.ko
    \\kernel/drivers/net/virtio_net.ko:
    \\
;

/// Enough of an ELF header for `moduleImage` to accept the file as an object.
/// Distinct per module so a test can tell which bytes were appended where.
fn elfModule(allocator: Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\x7fELF\x02\x01\x01\x00module:{s}", .{name});
}

/// The bytes a tree stores for `module_path`, in whatever compression the path
/// names, so a fixture is the file a real tree would hold rather than an object
/// wearing a compressed suffix.
fn storedModule(allocator: Allocator, module_path: []const u8, object: []const u8) ![]u8 {
    switch (kernel_modules.compressionOf(module_path) orelse .none) {
        .none => return allocator.dupe(u8, object),
        .gzip => {
            var compressed: std.Io.Writer.Allocating = try .initCapacity(allocator, 1024);
            errdefer compressed.deinit();
            var history: [std.compress.flate.max_window_len]u8 = undefined;
            var compressor = try std.compress.flate.Compress.init(
                &compressed.writer,
                &history,
                .gzip,
                .default,
            );
            try compressor.writer.writeAll(object);
            try compressor.finish();
            return compressed.toOwnedSlice();
        },
        // No fixture needs one, and writing bytes that only claim to be xz or
        // zstd is how the modular tests came to pass while proving nothing.
        .xz, .zstd => return allocator.dupe(u8, object),
    }
}

const ProbeImage = struct {
    releases: []const []const u8,
    builtin: ?[]const u8 = null,
    dep: ?[]const u8 = null,
    /// Module files to place under each release's tree, named by their path
    /// relative to `lib/modules/<release>`.
    modules: []const []const u8 = &.{},
    /// Written verbatim instead of a generated object, for the case where the
    /// tree holds something that is not a module.
    module_bytes: ?[]const u8 = null,
};

fn writeDriverProbeImage(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    image: ProbeImage,
) !void {
    var tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    try tree.putDirectory("lib", .{ .mode = 0o755 });
    try tree.putDirectory("lib/modules", .{ .mode = 0o755 });
    for (image.releases) |release| {
        const directory = try std.fmt.allocPrint(allocator, "lib/modules/{s}", .{release});
        defer allocator.free(directory);
        try tree.putDirectory(directory, .{ .mode = 0o755 });
        if (image.builtin) |bytes| {
            try putTreeFile(allocator, &tree, directory, "modules.builtin", bytes);
        }
        if (image.dep) |bytes| {
            try putTreeFile(allocator, &tree, directory, "modules.dep", bytes);
        }
        for (image.modules) |module_path| {
            const bytes = if (image.module_bytes) |literal|
                try allocator.dupe(u8, literal)
            else stored: {
                const object = try elfModule(allocator, kernel_modules.moduleName(module_path));
                defer allocator.free(object);
                break :stored try storedModule(allocator, module_path, object);
            };
            defer allocator.free(bytes);
            try putTreeFile(allocator, &tree, directory, module_path, bytes);
        }
    }

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, 16 * 1024 * 1024);
    _ = try ext4.populate(io, file, allocator, try tree.ext4View(), .{
        .offset = 0,
        .length = 16 * 1024 * 1024,
        .label = "drivers",
        .uuid = [_]u8{0x57} ** 16,
        .timestamp = 1_735_689_600,
    });
}

/// Writes `<directory>/<relative>`, creating the directories a module tree
/// nests its files in.
fn putTreeFile(
    allocator: Allocator,
    tree: *root_tree.RootTree,
    directory: []const u8,
    relative: []const u8,
    bytes: []const u8,
) !void {
    const full = try std.fs.path.join(allocator, &.{ directory, relative });
    defer allocator.free(full);

    var end = directory.len;
    while (std.mem.indexOfScalarPos(u8, full, end + 1, '/')) |slash| {
        try tree.putDirectory(full[0..slash], .{ .mode = 0o755 });
        end = slash;
    }
    try tree.putFileBytes(full, bytes, .{ .mode = 0o644 });
}

test "the disk transport is read from the image rather than assumed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-drivers.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Azure Linux: virtio-blk is a module, and virtio-scsi is built in, so the
    // transport that needs nothing inserted is the one that is used.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.6.139.1-1.azl3"},
        .builtin = azure_linux_builtin,
        .dep = "kernel/drivers/block/virtio_blk.ko.xz:\n",
        .modules = &.{"kernel/drivers/block/virtio_blk.ko.xz"},
    });
    var azure = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer azure.deinit(allocator);
    try std.testing.expectEqual(DiskTransport.virtio_scsi, azure.disk);
    try std.testing.expect(azure.network);
    // Nothing had to be inserted, so this run is the run it always was.
    try std.testing.expectEqual(@as(usize, 0), azure.modules.len);

    // A kernel with virtio-blk built in gets the simpler transport.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/block/virtio_blk.ko\nkernel/drivers/scsi/virtio_scsi.ko\n",
    });
    var both = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer both.deinit(allocator);
    try std.testing.expectEqual(DiskTransport.virtio_blk, both.disk);
    // Nothing claimed virtio-net, so a networked run must not be attempted.
    try std.testing.expect(!both.network);
    try std.testing.expectEqual(@as(usize, 0), both.modules.len);
}

test "a kernel that modularizes its drivers is served by its own module tree" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-modular.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        // Nothing this backend needs is built in, which is exactly the image
        // that used to be refused outright.
        .builtin = "kernel/fs/xfs/xfs.ko\n",
        .dep = modular_dep,
        .modules = &.{
            "kernel/drivers/virtio/virtio_pci.ko",
            "kernel/drivers/block/virtio_blk.ko",
            "kernel/drivers/scsi/scsi_mod.ko",
            "kernel/drivers/scsi/sd_mod.ko",
            "kernel/drivers/scsi/virtio_scsi.ko",
            "kernel/fs/mbcache.ko",
            "kernel/fs/jbd2/jbd2.ko",
            "kernel/fs/ext4/ext4.ko",
            "kernel/drivers/net/virtio_net.ko",
        },
    });

    var drivers = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .network_required = true,
    });
    defer drivers.deinit(allocator);

    // virtio-blk needs one module where virtio-scsi needs three, and neither
    // is built in, so the simpler transport wins.
    try std.testing.expectEqual(DiskTransport.virtio_blk, drivers.disk);
    try std.testing.expect(drivers.network);

    // The bus before the disk, the disk before the filesystem it carries, and
    // every dependency before what needs it.
    const expected = [_][]const u8{ "virtio_pci", "virtio_blk", "mbcache", "jbd2", "ext4", "virtio_net" };
    try std.testing.expectEqual(expected.len, drivers.modules.len);
    for (expected, drivers.modules, 0..) |name, module, index| {
        try std.testing.expectEqualStrings(name, module.name);
        const member = try std.fmt.allocPrint(
            allocator,
            "miz-module-{d:0>2}-{s}.ko",
            .{ index, name },
        );
        defer allocator.free(member);
        try std.testing.expectEqualStrings(member, module.member_path);

        // The bytes are the image's own, decompressed, and digested as loaded.
        const object = try elfModule(allocator, name);
        defer allocator.free(object);
        try std.testing.expectEqualStrings(object, module.bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(object, &digest, .{});
        try std.testing.expectEqualSlices(u8, &digest, &module.sha256);
        try std.testing.expect(std.mem.startsWith(u8, module.image_path, "lib/modules/6.1.0-cloud/"));
    }
}

test "the checksum driver ext4 asks for at mount time is loaded with it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-modular-crc32c.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // ext4 does not depend on a checksum driver by symbol -- `modules.dep`
    // says so -- but it asks the crypto API for "crc32c" by name as it mounts,
    // and a guest with no module loader cannot answer that later.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin = "kernel/drivers/virtio/virtio_pci.ko\nkernel/drivers/block/virtio_blk.ko\n",
        .dep =
        \\kernel/crypto/crc32c_generic.ko:
        \\kernel/fs/mbcache.ko:
        \\kernel/fs/jbd2/jbd2.ko:
        \\kernel/fs/ext4/ext4.ko: kernel/fs/mbcache.ko kernel/fs/jbd2/jbd2.ko
        \\
        ,
        .modules = &.{
            "kernel/crypto/crc32c_generic.ko",
            "kernel/fs/mbcache.ko",
            "kernel/fs/jbd2/jbd2.ko",
            "kernel/fs/ext4/ext4.ko",
        },
    });

    var drivers = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer drivers.deinit(allocator);

    const expected = [_][]const u8{ "mbcache", "jbd2", "ext4", "crc32c_generic" };
    try std.testing.expectEqual(expected.len, drivers.modules.len);
    for (expected, drivers.modules) |name, module| {
        try std.testing.expectEqualStrings(name, module.name);
    }
}

test "a kernel with the checksum driver built in inserts nothing for it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-builtin-crc32c.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin =
        \\kernel/drivers/virtio/virtio_pci.ko
        \\kernel/drivers/block/virtio_blk.ko
        \\kernel/crypto/crc32c_generic.ko
        \\
        ,
        .dep =
        \\kernel/crypto/crc32c_generic.ko:
        \\kernel/fs/ext4/ext4.ko:
        \\
        ,
        .modules = &.{
            "kernel/crypto/crc32c_generic.ko",
            "kernel/fs/ext4/ext4.ko",
        },
    });

    var drivers = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer drivers.deinit(allocator);

    // The tree holds a module the kernel already contains; inserting it would
    // be work that can only fail.
    try std.testing.expectEqual(@as(usize, 1), drivers.modules.len);
    try std.testing.expectEqualStrings("ext4", drivers.modules[0].name);
}

test "a modular virtio-scsi brings the SCSI disk driver with it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-modular-scsi.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // No virtio-blk at all, so the disks arrive over SCSI -- and a SCSI disk
    // is `/dev/sda` only once `sd_mod` is loaded, which `modules.dep` does not
    // say because it is not a dependency of the transport. The tree is stored
    // compressed, which is what most trees are.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n",
        .dep =
        \\kernel/drivers/scsi/scsi_mod.ko.gz:
        \\kernel/drivers/scsi/sd_mod.ko.gz: kernel/drivers/scsi/scsi_mod.ko.gz
        \\kernel/drivers/scsi/virtio_scsi.ko.gz: kernel/drivers/scsi/scsi_mod.ko.gz
        \\
        ,
        .modules = &.{
            "kernel/drivers/scsi/scsi_mod.ko.gz",
            "kernel/drivers/scsi/sd_mod.ko.gz",
            "kernel/drivers/scsi/virtio_scsi.ko.gz",
        },
    });

    var drivers = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer drivers.deinit(allocator);

    try std.testing.expectEqual(DiskTransport.virtio_scsi, drivers.disk);
    const expected = [_][]const u8{ "scsi_mod", "virtio_scsi", "sd_mod" };
    try std.testing.expectEqual(expected.len, drivers.modules.len);
    for (expected, drivers.modules) |name, module| {
        try std.testing.expectEqualStrings(name, module.name);

        // What is appended is the object, not the compressed file: the guest
        // kernel is not promised to have been built to decompress modules.
        const object = try elfModule(allocator, name);
        defer allocator.free(object);
        try std.testing.expectEqualStrings(object, module.bytes);
    }
}

test "an image whose kernel can drive no disk is refused rather than booted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-nodisk.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/net/virtio_net.ko\n",
    });
    try std.testing.expectError(error.NoDiskDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));

    // A near-miss name must not be mistaken for the driver itself.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/block/virtio_blk_helper.ko\n",
        .dep = "kernel/drivers/block/virtio_blk_helper.ko.xz:\n",
    });
    try std.testing.expectError(error.NoDiskDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));

    // virtio-scsi with no SCSI disk driver anywhere is a controller with no
    // disk behind it, which is the same refusal.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/scsi/virtio_scsi.ko\n",
    });
    try std.testing.expectError(error.NoDiskDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));
}

test "an image whose kernel cannot mount its own root filesystem is refused" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-nofs.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A kernel that neither builds ext4 in nor ships it: the agent would reach
    // its mount and be unable to complete it.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/block/virtio_blk.ko\nkernel/drivers/net/virtio_net.ko\n",
        .dep = "kernel/fs/xfs/xfs.ko.xz:\n",
    });
    try std.testing.expectError(error.NoRootFilesystemDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));
}

test "a kernel that cannot see the virtio bus is refused before it is booted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-nobus.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Every device this backend attaches is a PCI device, so a kernel with
    // neither a built-in nor a loadable virtio_pci sees none of them.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/block/virtio_blk.ko\n",
    });
    try std.testing.expectError(error.NoVirtioBusDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));
}

test "a networked run is refused when nothing can drive a network device" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-nonet.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.12.0-1.other"},
        .builtin = "kernel/fs/ext4/ext4.ko\nkernel/drivers/virtio/virtio_pci.ko\n" ++
            "kernel/drivers/block/virtio_blk.ko\n",
    });
    try std.testing.expectError(error.NoNetworkDriver, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .network_required = true,
    }));

    // The same image offline is fine: it is given no network device at all.
    var offline = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    });
    defer offline.deinit(allocator);
    try std.testing.expect(!offline.network);
}

test "a module the tree describes but does not hold is refused" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-missing-module.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin = "kernel/drivers/virtio/virtio_pci.ko\nkernel/drivers/block/virtio_blk.ko\n",
        .dep = "kernel/fs/ext4/ext4.ko.xz:\n",
    });
    try std.testing.expectError(error.ModuleFileUnreadable, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));
}

test "a module the host cannot read is refused rather than shipped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-unreadable-module.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // The guest can only decompress a module itself if its kernel was built
    // with CONFIG_MODULE_DECOMPRESS, which an image does not promise, so a
    // format the host cannot read is a refusal rather than a gamble.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin = "kernel/drivers/virtio/virtio_pci.ko\nkernel/drivers/block/virtio_blk.ko\n",
        .dep = "kernel/fs/ext4/ext4.ko.lz4:\n",
        .modules = &.{"kernel/fs/ext4/ext4.ko.lz4"},
    });
    try std.testing.expectError(
        error.UnsupportedModuleCompression,
        probeDrivers(allocator, io, .{ .raw_path = path, .root_partition_offset = 0 }),
    );

    // A file that is not an object at all is not a module either.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{"6.1.0-cloud"},
        .builtin = "kernel/drivers/virtio/virtio_pci.ko\nkernel/drivers/block/virtio_blk.ko\n",
        .dep = "kernel/fs/ext4/ext4.ko:\n",
        .modules = &.{"kernel/fs/ext4/ext4.ko"},
        .module_bytes = "#!/bin/sh\n",
    });
    try std.testing.expectError(
        error.ModuleNotAnObject,
        probeDrivers(allocator, io, .{ .raw_path = path, .root_partition_offset = 0 }),
    );
}

test "an image that does not say what its kernel can drive is not guessed at" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-vm-payload-unknown.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // No modules.builtin at all: no evidence either way.
    try writeDriverProbeImage(allocator, io, path, .{ .releases = &.{"6.12.0-1.other"} });
    try std.testing.expectError(error.GuestDriversUndetermined, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));

    // Several module trees and no release named: which kernel boots decides
    // the answer, so the caller must say which one.
    try writeDriverProbeImage(allocator, io, path, .{
        .releases = &.{ "6.12.0-1.other", "6.6.139.1-1.azl3" },
        .builtin = azure_linux_builtin,
    });
    try std.testing.expectError(error.GuestDriversUndetermined, probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
    }));
    var named = try probeDrivers(allocator, io, .{
        .raw_path = path,
        .root_partition_offset = 0,
        .kernel_release = "6.6.139.1-1.azl3",
    });
    defer named.deinit(allocator);
    try std.testing.expectEqual(DiskTransport.virtio_scsi, named.disk);
}
