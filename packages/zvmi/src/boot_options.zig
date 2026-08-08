//! Adding kernel command-line options to the boot entries an image already
//! carries.
//!
//! A fresh build renders its command line from the request, so extra options
//! cost nothing there: `bootconfig.renderKernelOptions` simply appends them
//! while the entries are being generated. A preserved image has no such
//! moment. Its entries already exist, and the authoritative copies of a
//! zvmi-built image live on the ESP -- `EFI/BOOT/grub.cfg`, the vendor
//! `grub.cfg` copies beside each bootloader, and `loader/entries/*.conf` --
//! each with the command line written inline. Changing the command line of
//! such an image means editing those files.
//!
//! Three deliberate choices shape this module:
//!
//! * **Appending, never regenerating.** The same argument `identity_rewrite`
//!   makes for `/etc/fstab` applies with more force here: a boot entry
//!   carries `root=`, verity parameters and whatever the image was built
//!   with, and re-emitting it from a parsed model would have to reproduce all
//!   of that exactly to avoid replacing a bootable entry with an unbootable
//!   one. Appending to the end of the existing option text changes what was
//!   asked for and nothing else, and a later duplicate argument wins on the
//!   kernel command line, which is what makes appending well defined.
//! * **Every entry, or none.** A file the rewriter recognizes as an entry but
//!   cannot edit fails the run by name. Editing three of four entries would
//!   produce an image that boots with the requested options only if the
//!   default entry happened to be one of the three.
//! * **A verification pass has the final say.** Every file is read back after
//!   the write and every entry re-checked, because the failure mode this
//!   prevents -- an image that boots without the argument it was asked to
//!   boot with -- is otherwise discovered by a human reading `/proc/cmdline`.
//!
//! What this module cannot do is refused rather than approximated. A unified
//! kernel image carries its command line inside a PE section of a binary that
//! is frequently signed, so an image with one is refused: appending there
//! means rebuilding and re-signing the UKI, which is a fresh build's job.

const std = @import("std");
const Io = std.Io;

const fat32 = @import("fat32.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const selinux = @import("selinux.zig");

const Image = image_mod.Image;

/// Longest option text this module will append. A kernel command line is
/// itself bounded (`CONFIG_COMMAND_LINE_SIZE` is 2048 on x86_64), so text
/// past this could not be honored by the kernel that received it.
pub const max_options_bytes: usize = 1024;

/// Upper bound on a single boot configuration file. These are generated text
/// a few kilobytes long; anything past this is not one, and refusing beats
/// reading an unbounded file into memory.
pub const max_config_bytes: usize = 1024 * 1024;

/// Upper bound on the entry files the rewriter will consider. A real ESP
/// carries a handful; a number past this means the scan found something that
/// is not a boot configuration directory.
pub const max_entry_files: usize = 256;

/// Longest path a diagnostic will carry, copied rather than allocated so it
/// survives the failure path that produced it.
pub const max_path_bytes: usize = 128;

pub const Error = error{
    /// The option text is empty, too long, or carries a character that
    /// cannot appear on a kernel command line written into a line-oriented
    /// configuration file.
    InvalidKernelOptions,
    /// The image has no GPT, so it has no ESP to find. A preserved MBR image
    /// is the usual reason.
    MissingPartitionTable,
    /// The image has a GPT with no EFI System Partition.
    MissingEspPartition,
    /// The GPT names an ESP whose sector range overflows or reaches past the
    /// end of the image. Nothing validates partition bounds between the entry
    /// array's checksum and this module, so they are checked here rather than
    /// trusted into arithmetic that would wrap.
    InvalidEspBounds,
    /// The ESP carries a unified kernel image, whose command line is inside
    /// the binary rather than in a configuration file.
    UnsupportedUnifiedKernelImage,
    /// The ESP carries no boot entry this module recognizes.
    MissingBootEntry,
    /// A recognized entry file carries no line the append could apply to.
    UnsupportedBootEntry,
    /// A configuration file is larger than `max_config_bytes`.
    ConfigurationTooLarge,
    /// The ESP holds more candidate entry files than `max_entry_files`.
    TooManyEntryFiles,
    /// The verification pass found an entry that does not carry the options
    /// after the rewrite. Always a bug in this module or a filesystem that
    /// did not persist a write, never a property of the request.
    KernelOptionsNotApplied,
};

pub const ApplyError = Error ||
    std.mem.Allocator.Error ||
    fat32.OpenError ||
    fat32.ListError ||
    fat32.ReadFileError ||
    fat32.MutationError;

/// What the rewrite changed. Counts rather than paths, because the caller
/// records this in provenance where an unbounded list of ESP paths would be
/// noise; the one path that matters on a failure is carried by `Diagnostic`.
pub const Report = struct {
    /// GRUB `linux`/`linux16`/`linuxefi` lines the append reached.
    grub_entries: usize = 0,
    /// BLS `options` lines the append reached.
    bls_entries: usize = 0,
    /// Entries that already ended with exactly this option text and were
    /// left alone. Appending again would put the same argument on the
    /// command line twice for no effect.
    entries_already_current: usize = 0,
    files_rewritten: usize = 0,
    /// Files the verification pass read back in full.
    verified_files: usize = 0,

    pub fn entryCount(self: Report) usize {
        return self.grub_entries + self.bls_entries;
    }
};

/// The file that stopped the run, carried by value so the caller still has it
/// after the filesystem it was found on is closed.
pub const Diagnostic = struct {
    /// The first file the rewriter could not handle. Later ones are not
    /// recorded: the run stops at the first, so a second would describe a
    /// state that never existed.
    file: ?File = null,

    pub const File = struct {
        path_buffer: [max_path_bytes]u8 = undefined,
        path_length: usize = 0,
        path_truncated: bool = false,

        pub fn path(self: *const File) []const u8 {
            return self.path_buffer[0..self.path_length];
        }
    };

    pub fn record(self: *Diagnostic, path: []const u8) void {
        if (self.file != null) return;
        var entry = File{};
        entry.path_length = @min(path.len, entry.path_buffer.len);
        entry.path_truncated = path.len > entry.path_buffer.len;
        @memcpy(entry.path_buffer[0..entry.path_length], path[0..entry.path_length]);
        self.file = entry;
    }
};

/// Rejects option text that could not be appended without changing something
/// other than the command line. Callable before any image exists, so a
/// request is refused at validation rather than partway through a build.
pub fn validateOptions(options: []const u8) Error!void {
    if (options.len == 0 or options.len > max_options_bytes) return error.InvalidKernelOptions;
    // Leading or trailing whitespace would make the appended text and the
    // recorded text differ, so the request is corrected by its author rather
    // than silently by this module.
    if (std.ascii.isWhitespace(options[0]) or std.ascii.isWhitespace(options[options.len - 1])) {
        return error.InvalidKernelOptions;
    }
    for (options) |byte| {
        // A newline would end the entry line and turn the remainder into a
        // configuration directive; the other control characters are not
        // representable in these files at all.
        if (byte < 0x20 or byte == 0x7f) return error.InvalidKernelOptions;
    }
}

/// Appends `options` to every boot entry on the image's ESP.
///
/// `image` must be the raw stage of an image, open for writing: this edits
/// the FAT32 filesystem in place, and a failure leaves the stage partially
/// rewritten. That is safe only because every caller discards the stage on
/// any error rather than publishing it.
pub fn apply(
    allocator: std.mem.Allocator,
    io: Io,
    image: *Image,
    options: []const u8,
    diagnostic: ?*Diagnostic,
) ApplyError!Report {
    try validateOptions(options);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const suffix = try std.fmt.allocPrint(arena, " {s}", .{options});
    var files = std.array_list.Managed(EntryFile).init(arena);
    var filesystem = try openEntryFiles(arena, io, image, &files);

    var report = Report{};
    for (files.items) |file| {
        const contents = try readConfig(&filesystem, io, arena, file.path);
        const outcome = try rewriteContents(arena, file.kind, contents, suffix);
        if (outcome.entries == 0) {
            if (diagnostic) |sink| sink.record(file.path);
            return error.UnsupportedBootEntry;
        }
        switch (file.kind) {
            .grub => report.grub_entries += outcome.entries,
            .bls => report.bls_entries += outcome.entries,
        }
        report.entries_already_current += outcome.already_current;
        if (outcome.text) |text| {
            // FAT32 has no replace-in-place for a file that changed length,
            // so the old entry is removed first. A failure between the two
            // discards the stage, which is why the window is acceptable here
            // and would not be on a published image.
            try filesystem.deletePath(io, file.path);
            try filesystem.writeFile(io, file.path, text);
            report.files_rewritten += 1;
        }
    }
    if (report.entryCount() == 0) return error.MissingBootEntry;

    for (files.items) |file| {
        const contents = try readConfig(&filesystem, io, arena, file.path);
        try verifyFile(file.kind, contents, suffix, file.path, diagnostic);
        report.verified_files += 1;
    }
    return report;
}

/// What a source image can accept, answered without changing it. Used to
/// refuse a request in preflight, where the answer costs a read of the
/// source and nothing has been staged yet.
pub const Inspection = struct {
    grub_files: usize = 0,
    bls_files: usize = 0,
    entries: usize = 0,
};

/// Runs every check `apply` would run, and none of its writes. `image` may be
/// open read-only: locating the ESP and reading its boot configuration never
/// writes, which is what makes this usable on a caller's source image.
pub fn inspect(
    allocator: std.mem.Allocator,
    io: Io,
    image: *Image,
    diagnostic: ?*Diagnostic,
) ApplyError!Inspection {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var files = std.array_list.Managed(EntryFile).init(arena);
    var filesystem = try openEntryFiles(arena, io, image, &files);

    var inspection = Inspection{};
    for (files.items) |file| {
        const contents = try readConfig(&filesystem, io, arena, file.path);
        const entries = countEntryLines(file.kind, contents);
        if (entries == 0) {
            if (diagnostic) |sink| sink.record(file.path);
            return error.UnsupportedBootEntry;
        }
        switch (file.kind) {
            .grub => inspection.grub_files += 1,
            .bls => inspection.bls_files += 1,
        }
        inspection.entries += entries;
    }
    return inspection;
}

/// Whether any boot entry the image carries switches SELinux off on the kernel
/// command line.
///
/// Read-only, over the same entry files `inspect` reads, so a SELinux
/// configuration change can record that the image it produced will boot with
/// SELinux off whatever it wrote into `/etc/selinux/config`. Nothing here
/// edits a command line: that is a different request with its own model.
pub fn selinuxDisabledOnCommandLine(
    allocator: std.mem.Allocator,
    io: Io,
    image: *Image,
) ApplyError!bool {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var files = std.array_list.Managed(EntryFile).init(arena);
    var filesystem = try openEntryFiles(arena, io, image, &files);
    for (files.items) |file| {
        const contents = try readConfig(&filesystem, io, arena, file.path);
        if (selinux.carriesDisablingKernelOption(contents)) return true;
    }
    return false;
}

/// Opens the ESP and fills `files` with every boot entry file on it, refusing
/// an image this module cannot describe before the caller decides what to do
/// with the result.
fn openEntryFiles(
    arena: std.mem.Allocator,
    io: Io,
    image: *Image,
    files: *std.array_list.Managed(EntryFile),
) ApplyError!fat32.FileSystem {
    const esp = try findEsp(image.*, io, arena);
    var filesystem = try fat32.open(image, io, .{ .offset = esp.offset, .length = esp.length });
    try refuseUnifiedKernelImages(&filesystem, io, arena);
    try collectGrubConfigs(&filesystem, io, arena, files);
    try collectBlsEntries(&filesystem, io, arena, files);
    if (files.items.len == 0) return error.MissingBootEntry;
    return filesystem;
}

const EspRegion = struct {
    offset: u64,
    length: u64,
};

fn findEsp(image: Image, io: Io, allocator: std.mem.Allocator) ApplyError!EspRegion {
    const parsed = gpt.readGpt(image, io, allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MissingPartitionTable,
    };
    for (parsed.partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp)) continue;
        if (partition.last_lba < partition.first_lba) return error.InvalidEspBounds;
        const sectors = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
            return error.InvalidEspBounds;
        const offset = std.math.mul(u64, partition.first_lba, gpt.sector_size) catch
            return error.InvalidEspBounds;
        const length = std.math.mul(u64, sectors, gpt.sector_size) catch
            return error.InvalidEspBounds;
        const end = std.math.add(u64, offset, length) catch return error.InvalidEspBounds;
        if (end > image.virtual_size) return error.InvalidEspBounds;
        return .{ .offset = offset, .length = length };
    }
    return error.MissingEspPartition;
}

const EntryKind = enum { grub, bls };

const EntryFile = struct {
    path: []const u8,
    kind: EntryKind,
};

/// The directory `bootconfig` writes unified kernel images into by default,
/// and the one every generator this module has met uses.
const uki_directory = "EFI/Linux";

fn refuseUnifiedKernelImages(
    filesystem: *fat32.FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
) ApplyError!void {
    const entries = listDir(filesystem, io, allocator, uki_directory) catch |err| switch (err) {
        error.PathNotFound, error.NotDirectory => return,
        else => |other| return other,
    };
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (std.ascii.endsWithIgnoreCase(entry.name, ".efi")) {
            return error.UnsupportedUnifiedKernelImage;
        }
    }
}

fn collectGrubConfigs(
    filesystem: *fat32.FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    files: *std.array_list.Managed(EntryFile),
) ApplyError!void {
    // The vendor copies matter as much as `EFI/BOOT/grub.cfg`: which one the
    // firmware reads depends on which bootloader it launched, so an image
    // whose vendor copy kept the old command line boots with the old command
    // line on exactly the machines that use it.
    const vendors = listDir(filesystem, io, allocator, "EFI") catch |err| switch (err) {
        error.PathNotFound, error.NotDirectory => return,
        else => |other| return other,
    };
    for (vendors) |vendor| {
        if (vendor.kind != .directory) continue;
        const vendor_path = try std.fmt.allocPrint(allocator, "EFI/{s}", .{vendor.name});
        const entries = listDir(filesystem, io, allocator, vendor_path) catch |err| switch (err) {
            error.PathNotFound, error.NotDirectory => continue,
            else => |other| return other,
        };
        for (entries) |entry| {
            if (entry.kind != .file) continue;
            if (!std.ascii.eqlIgnoreCase(entry.name, "grub.cfg")) continue;
            if (files.items.len >= max_entry_files) return error.TooManyEntryFiles;
            try files.append(.{
                .path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ vendor_path, entry.name }),
                .kind = .grub,
            });
        }
    }
}

fn collectBlsEntries(
    filesystem: *fat32.FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    files: *std.array_list.Managed(EntryFile),
) ApplyError!void {
    const entries = listDir(filesystem, io, allocator, "loader/entries") catch |err| switch (err) {
        error.PathNotFound, error.NotDirectory => return,
        else => |other| return other,
    };
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (!std.ascii.endsWithIgnoreCase(entry.name, ".conf")) continue;
        const path = try std.fmt.allocPrint(allocator, "loader/entries/{s}", .{entry.name});
        if (files.items.len >= max_entry_files) return error.TooManyEntryFiles;
        try files.append(.{ .path = path, .kind = .bls });
    }
}

fn listDir(
    filesystem: *fat32.FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) ApplyError![]fat32.DirEntry {
    return filesystem.listDirAllocLimited(io, allocator, path, max_entry_files) catch |err| switch (err) {
        error.DirectoryTooLarge => error.TooManyEntryFiles,
        else => |other| other,
    };
}

fn readConfig(
    filesystem: *fat32.FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) ApplyError![]const u8 {
    const contents = try filesystem.readFileAlloc(io, allocator, path);
    if (contents.len > max_config_bytes) return error.ConfigurationTooLarge;
    return contents;
}

const FileOutcome = struct {
    /// Lines in this file the append applies to, whether or not it had to
    /// change them.
    entries: usize = 0,
    already_current: usize = 0,
    /// The new contents, or null when every entry already carried the
    /// options and rewriting would have reproduced the file byte for byte.
    text: ?[]const u8 = null,
};

/// Appends `suffix` to each entry line, reproducing every other byte exactly.
/// Line endings are preserved as found, including a file that uses CRLF or
/// one whose last line has no terminator, because the only intended
/// difference between the input and the output is the option text.
fn rewriteContents(
    allocator: std.mem.Allocator,
    kind: EntryKind,
    contents: []const u8,
    suffix: []const u8,
) std.mem.Allocator.Error!FileOutcome {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    var outcome = FileOutcome{};
    var changed = false;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) out.writer.writeByte('\n') catch return error.OutOfMemory;
        first = false;

        const has_cr = line.len != 0 and line[line.len - 1] == '\r';
        const body = if (has_cr) line[0 .. line.len - 1] else line;
        if (!isEntryLine(kind, body)) {
            out.writer.writeAll(line) catch return error.OutOfMemory;
            continue;
        }

        outcome.entries += 1;
        if (std.mem.endsWith(u8, body, suffix)) {
            outcome.already_current += 1;
            out.writer.writeAll(line) catch return error.OutOfMemory;
            continue;
        }
        changed = true;
        out.writer.writeAll(body) catch return error.OutOfMemory;
        out.writer.writeAll(suffix) catch return error.OutOfMemory;
        if (has_cr) out.writer.writeByte('\r') catch return error.OutOfMemory;
    }

    if (changed) {
        outcome.text = try out.toOwnedSlice();
    } else {
        out.deinit();
    }
    return outcome;
}

/// The GRUB commands that boot a kernel, and the BLS key that carries its
/// command line. `linux16` and `linuxefi` appear in distro configurations
/// rather than in anything zvmi generates, and are recognized because
/// leaving them unedited would produce exactly the half-updated image this
/// module refuses to publish.
fn isEntryLine(kind: EntryKind, line: []const u8) bool {
    const trimmed = std.mem.trimStart(u8, line, " \t");
    const keywords: []const []const u8 = switch (kind) {
        .grub => &.{ "linux", "linux16", "linuxefi" },
        .bls => &.{"options"},
    };
    for (keywords) |keyword| {
        if (!std.mem.startsWith(u8, trimmed, keyword)) continue;
        const rest = trimmed[keyword.len..];
        // A keyword with no argument carries no command line to append to,
        // and `linuxefi_something` is a different command entirely.
        if (rest.len == 0) continue;
        if (rest[0] != ' ' and rest[0] != '\t') continue;
        if (std.mem.trim(u8, rest, " \t").len == 0) continue;
        return true;
    }
    return false;
}

/// GRUB entries in `contents` carrying `options` as a whole-word run
/// anywhere in the command line.
///
/// Public because the `unsafe_chroot` backend regenerates a distro's
/// `grub.cfg` with the distro's own tooling rather than editing it, and then
/// has to answer the same question about the result: what a GRUB entry line
/// looks like should have one definition in this repository, not two that
/// drift.
///
/// Anywhere, rather than at the end as `apply` guarantees for the files it
/// writes itself, because a generator composes the line from several
/// variables: `/etc/grub.d/10_linux` emits
/// `"${GRUB_CMDLINE_LINUX} ${GRUB_CMDLINE_LINUX_DEFAULT}"` for its normal
/// entries, so options appended to the first variable land in the middle of
/// the entry. Requiring a suffix there would fail a run that had applied the
/// change correctly.
pub fn countGrubEntriesCarrying(contents: []const u8, options: []const u8) usize {
    if (options.len == 0) return 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var entries: usize = 0;
    while (lines.next()) |line| {
        const has_cr = line.len != 0 and line[line.len - 1] == '\r';
        const body = if (has_cr) line[0 .. line.len - 1] else line;
        if (!isEntryLine(.grub, body)) continue;
        if (containsWordRun(body, options)) entries += 1;
    }
    return entries;
}

/// Whether `needle` appears in `haystack` bounded by whitespace or the ends
/// of the text on both sides, so `quiet` is not found inside `noquiet` and
/// `console=ttyS0` is not found inside `console=ttyS0,115200`.
fn containsWordRun(haystack: []const u8, needle: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, offset, needle)) |index| {
        defer offset = index + 1;
        if (index != 0) {
            const preceding = haystack[index - 1];
            if (preceding != ' ' and preceding != '\t') continue;
        }
        const end = index + needle.len;
        if (end != haystack.len) {
            const following = haystack[end];
            if (following != ' ' and following != '\t') continue;
        }
        return true;
    }
    return false;
}

fn countEntryLines(kind: EntryKind, contents: []const u8) usize {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var entries: usize = 0;
    while (lines.next()) |line| {
        const has_cr = line.len != 0 and line[line.len - 1] == '\r';
        if (isEntryLine(kind, if (has_cr) line[0 .. line.len - 1] else line)) entries += 1;
    }
    return entries;
}

fn verifyFile(
    kind: EntryKind,
    contents: []const u8,
    suffix: []const u8,
    path: []const u8,
    diagnostic: ?*Diagnostic,
) Error!void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var entries: usize = 0;
    while (lines.next()) |line| {
        const has_cr = line.len != 0 and line[line.len - 1] == '\r';
        const body = if (has_cr) line[0 .. line.len - 1] else line;
        if (!isEntryLine(kind, body)) continue;
        entries += 1;
        if (!std.mem.endsWith(u8, body, suffix)) {
            if (diagnostic) |sink| sink.record(path);
            return error.KernelOptionsNotApplied;
        }
    }
    if (entries == 0) {
        if (diagnostic) |sink| sink.record(path);
        return error.KernelOptionsNotApplied;
    }
}

const test_esp_first_lba: u64 = 2048;
const test_esp_sectors: u64 = 64 * 2048;
const test_disk_size: u64 = (test_esp_first_lba + test_esp_sectors + 2048) * gpt.sector_size;

const test_grub_cfg =
    "set default=0\nset timeout=5\n\ninsmod part_gpt\ninsmod ext2\n" ++
    "search --no-floppy --fs-uuid --set=kernel_root 1111-2222\n\n" ++
    "menuentry 'zvmi' --id 'zvmi-1' {\n" ++
    "    linux ($kernel_root)/boot/vmlinuz root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001\n" ++
    "    initrd ($kernel_root)/boot/initrd.img\n" ++
    "}\n\n";

const test_bls_entry =
    "title zvmi\nversion 6.1.0\nlinux /boot/vmlinuz\ninitrd /boot/initrd.img\n" ++
    "options root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001\n";

const TestEsp = struct {
    image: Image,
    offset: u64,
    length: u64,
};

fn createTestEspImage(io: Io, path: []const u8) !TestEsp {
    var image = try Image.createExclusive(io, path, .raw, test_disk_size, .{});
    errdefer image.close(io);
    const specs = [_]gpt.PartitionSpec{.{
        .type_guid = guid.esp,
        .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
        .size_sectors = @intCast(test_esp_sectors),
        .name_utf16le = gpt.asciiName("EFI System"),
    }};
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &image,
        io,
        guid.parse("22222222-2222-2222-2222-222222222222"),
        &specs,
        &placements,
    );
    const offset = placements[0].first_lba * gpt.sector_size;
    const length = (placements[0].last_lba - placements[0].first_lba + 1) * gpt.sector_size;
    try fat32.format(&image, io, .{ .partition_offset = offset, .partition_len = length });
    return .{ .image = image, .offset = offset, .length = length };
}

fn openTestEsp(target: *TestEsp, io: Io) !fat32.FileSystem {
    return fat32.open(&target.image, io, .{ .offset = target.offset, .length = target.length });
}

fn writeTestFile(filesystem: *fat32.FileSystem, io: Io, path: []const u8, contents: []const u8) !void {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    if (slash) |index| try filesystem.createDir(io, path[0..index]);
    try filesystem.writeFile(io, path, contents);
}

fn readTestFile(filesystem: *fat32.FileSystem, io: Io, path: []const u8) ![]u8 {
    return filesystem.readFileAlloc(io, std.testing.allocator, path);
}

test "an append reaches the default, vendor and BLS copies of the command line" {
    const io = std.testing.io;
    const path = "test-boot-options-append.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/grub.cfg", test_grub_cfg);
        try writeTestFile(&esp, io, "EFI/Acme/grub.cfg", test_grub_cfg);
        try writeTestFile(&esp, io, "loader/entries/zvmi-1.conf", test_bls_entry);
    }

    const report = try apply(std.testing.allocator, io, image, "console=ttyS0 quiet", null);
    try std.testing.expectEqual(@as(usize, 2), report.grub_entries);
    try std.testing.expectEqual(@as(usize, 1), report.bls_entries);
    try std.testing.expectEqual(@as(usize, 0), report.entries_already_current);
    try std.testing.expectEqual(@as(usize, 3), report.files_rewritten);
    try std.testing.expectEqual(@as(usize, 3), report.verified_files);

    var esp = try openTestEsp(&target, io);
    for ([_][]const u8{ "EFI/BOOT/grub.cfg", "EFI/Acme/grub.cfg" }) |cfg_path| {
        const contents = try readTestFile(&esp, io, cfg_path);
        defer std.testing.allocator.free(contents);
        try std.testing.expect(std.mem.containsAtLeast(
            u8,
            contents,
            1,
            "    linux ($kernel_root)/boot/vmlinuz root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001 console=ttyS0 quiet\n",
        ));
        // Every other byte is reproduced, including the initrd line the
        // append must not touch.
        try std.testing.expect(std.mem.containsAtLeast(u8, contents, 1, "    initrd ($kernel_root)/boot/initrd.img\n"));
        try std.testing.expect(std.mem.containsAtLeast(u8, contents, 1, "insmod part_gpt\n"));
    }
    const bls = try readTestFile(&esp, io, "loader/entries/zvmi-1.conf");
    defer std.testing.allocator.free(bls);
    try std.testing.expectEqualStrings(
        "title zvmi\nversion 6.1.0\nlinux /boot/vmlinuz\ninitrd /boot/initrd.img\n" ++
            "options root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001 console=ttyS0 quiet\n",
        bls,
    );
}

test "an entry that already carries the options is left exactly as it was" {
    const io = std.testing.io;
    const path = "test-boot-options-idempotent.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/grub.cfg", test_grub_cfg);
        try writeTestFile(&esp, io, "loader/entries/zvmi-1.conf", test_bls_entry);
    }

    const first = try apply(std.testing.allocator, io, image, "quiet", null);
    try std.testing.expectEqual(@as(usize, 2), first.files_rewritten);
    try std.testing.expectEqual(@as(usize, 0), first.entries_already_current);

    var before = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (before.items) |item| std.testing.allocator.free(item);
        before.deinit();
    }
    {
        var esp = try openTestEsp(&target, io);
        try before.append(try readTestFile(&esp, io, "EFI/BOOT/grub.cfg"));
        try before.append(try readTestFile(&esp, io, "loader/entries/zvmi-1.conf"));
    }

    const second = try apply(std.testing.allocator, io, image, "quiet", null);
    try std.testing.expectEqual(@as(usize, 0), second.files_rewritten);
    try std.testing.expectEqual(@as(usize, 2), second.entries_already_current);
    try std.testing.expectEqual(@as(usize, 2), second.verified_files);

    var esp = try openTestEsp(&target, io);
    for ([_][]const u8{ "EFI/BOOT/grub.cfg", "loader/entries/zvmi-1.conf" }, before.items) |file_path, expected| {
        const contents = try readTestFile(&esp, io, file_path);
        defer std.testing.allocator.free(contents);
        try std.testing.expectEqualStrings(expected, contents);
    }
}

test "a unified kernel image is refused rather than left carrying the old command line" {
    const io = std.testing.io;
    const path = "test-boot-options-uki.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/grub.cfg", test_grub_cfg);
        try writeTestFile(&esp, io, "EFI/Linux/zvmi-6.1.0.efi", "MZ not-really-a-uki");
    }

    try std.testing.expectError(
        error.UnsupportedUnifiedKernelImage,
        apply(std.testing.allocator, io, image, "quiet", null),
    );
}

test "a recognized configuration with no kernel line fails by name" {
    const io = std.testing.io;
    const path = "test-boot-options-no-kernel-line.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/grub.cfg", test_grub_cfg);
        try writeTestFile(&esp, io, "EFI/Acme/grub.cfg", "search --no-floppy --fs-uuid --set=root 1111\nconfigfile ($root)/boot/grub2/grub.cfg\n");
    }

    var diagnostic = Diagnostic{};
    try std.testing.expectError(
        error.UnsupportedBootEntry,
        apply(std.testing.allocator, io, image, "quiet", &diagnostic),
    );
    try std.testing.expectEqualStrings("EFI/Acme/grub.cfg", diagnostic.file.?.path());
}

test "an image with no ESP carries no command line to change" {
    const io = std.testing.io;
    const path = "test-boot-options-no-esp.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var image = try Image.createExclusive(io, path, .raw, test_disk_size, .{});
    defer image.close(io);
    try std.testing.expectError(
        error.MissingPartitionTable,
        apply(std.testing.allocator, io, &image, "quiet", null),
    );

    const specs = [_]gpt.PartitionSpec{.{
        .type_guid = guid.parse("0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
        .unique_guid = guid.parse("33333333-3333-3333-3333-333333333333"),
        .size_sectors = 2048,
        .name_utf16le = gpt.asciiName("root"),
    }};
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(&image, io, guid.parse("44444444-4444-4444-4444-444444444444"), &specs, &placements);
    try std.testing.expectError(
        error.MissingEspPartition,
        apply(std.testing.allocator, io, &image, "quiet", null),
    );
}

test "counting regenerated entries requires the options on a word boundary" {
    const generated =
        "menuentry 'a' {\n" ++
        "\tlinux /vmlinuz-6.1 root=UUID=1111 console=ttyS0 quiet\n" ++
        "}\n" ++
        "menuentry 'b (recovery)' {\n" ++
        "\tlinux /vmlinuz-6.1 root=UUID=1111 console=ttyS0 quiet\n" ++
        "}\n" ++
        "menuentry 'c' {\n" ++
        "\tlinux /vmlinuz-6.0 root=UUID=1111\n" ++
        "}\n";
    try std.testing.expectEqual(@as(usize, 2), countGrubEntriesCarrying(generated, "console=ttyS0 quiet"));
    // `quiet` ends two of the lines, but only as the tail of the declared
    // text, so asking for `iet` must not find it.
    try std.testing.expectEqual(@as(usize, 2), countGrubEntriesCarrying(generated, "quiet"));
    try std.testing.expectEqual(@as(usize, 0), countGrubEntriesCarrying(generated, "iet"));
    try std.testing.expectEqual(@as(usize, 0), countGrubEntriesCarrying(generated, ""));
    // Only the commands that boot a kernel count. An `initrd` line carrying
    // the same text is not an entry.
    try std.testing.expectEqual(
        @as(usize, 0),
        countGrubEntriesCarrying("\tinitrd /initramfs-6.1.img quiet\n", "quiet"),
    );
    // A real generator composes the line from `${GRUB_CMDLINE_LINUX}` and
    // `${GRUB_CMDLINE_LINUX_DEFAULT}`, so options appended to the first land
    // in the middle of the entry and still count.
    try std.testing.expectEqual(
        @as(usize, 1),
        countGrubEntriesCarrying(
            "\tlinux /vmlinuz-6.1 root=UUID=1 ro quiet console=tty0\n",
            "quiet",
        ),
    );
    // A run that is only part of a longer word is not the option.
    try std.testing.expectEqual(
        @as(usize, 0),
        countGrubEntriesCarrying("\tlinux /vmlinuz-6.1 ro noquiet\n", "quiet"),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        countGrubEntriesCarrying("\tlinux /vmlinuz-6.1 console=ttyS0,115200\n", "console=ttyS0"),
    );
}

test "an ESP whose declared sectors run past the disk is refused rather than trusted" {
    const io = std.testing.io;
    const path = "test-boot-options-bounds.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/grub.cfg", test_grub_cfg);
    }

    // Nothing between the entry array's checksum and this module validates a
    // partition's sector range, so a corrupt or crafted table can name one
    // that overflows the byte arithmetic. Restate the table with a last LBA
    // no disk has, checksums and all, and require a named refusal rather than
    // a wrapped offset or a panic.
    var header_sector: [gpt.sector_size]u8 = undefined;
    _ = try image.pread(io, &header_sector, gpt.sector_size);
    var header = try gpt.Header.decode(&header_sector);
    const array_bytes = header.num_partition_entries * header.partition_entry_size;
    const array = try std.testing.allocator.alloc(u8, array_bytes);
    defer std.testing.allocator.free(array);
    _ = try image.pread(io, array, header.partition_entry_lba * gpt.sector_size);
    std.mem.writeInt(u64, array[40..48], std.math.maxInt(u64), .little);
    try image.pwrite(io, array, header.partition_entry_lba * gpt.sector_size);
    header.partition_array_crc32 = std.hash.crc.Crc32.hash(array);
    try image.pwrite(io, &header.encode(), gpt.sector_size);

    try std.testing.expectError(
        error.InvalidEspBounds,
        apply(std.testing.allocator, io, image, "console=ttyS0", null),
    );
}

test "an ESP with no boot entry at all is refused" {
    const io = std.testing.io;
    const path = "test-boot-options-no-entries.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var target = try createTestEspImage(io, path);
    defer target.image.close(io);
    const image = &target.image;
    {
        var esp = try openTestEsp(&target, io);
        try writeTestFile(&esp, io, "EFI/BOOT/BOOTX64.EFI", "not a configuration");
    }

    try std.testing.expectError(
        error.MissingBootEntry,
        apply(std.testing.allocator, io, image, "quiet", null),
    );
}

test "option text that could change more than the command line is refused" {
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions(""));
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions(" quiet"));
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions("quiet "));
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions("quiet\nmenuentry 'x' {"));
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions("quiet\x00"));
    try std.testing.expectError(error.InvalidKernelOptions, validateOptions("q" ** (max_options_bytes + 1)));
    try validateOptions("console=ttyS0 quiet");
}

test "a CRLF configuration keeps its line endings" {
    const contents = "menuentry 'x' {\r\n    linux /vmlinuz root=PARTUUID=a\r\n}\r\n";
    const outcome = try rewriteContents(std.testing.allocator, .grub, contents, " quiet");
    defer if (outcome.text) |text| std.testing.allocator.free(@constCast(text));
    try std.testing.expectEqual(@as(usize, 1), outcome.entries);
    try std.testing.expectEqualStrings(
        "menuentry 'x' {\r\n    linux /vmlinuz root=PARTUUID=a quiet\r\n}\r\n",
        outcome.text.?,
    );
}

test "a keyword with no argument is not an entry line" {
    try std.testing.expect(!isEntryLine(.grub, "    linux"));
    try std.testing.expect(!isEntryLine(.grub, "    linux   "));
    try std.testing.expect(!isEntryLine(.grub, "    linuxefi_helper /vmlinuz"));
    try std.testing.expect(!isEntryLine(.bls, "options"));
    try std.testing.expect(!isEntryLine(.bls, "optionsroot=a"));
    try std.testing.expect(isEntryLine(.grub, "    linux16 /vmlinuz root=a"));
    try std.testing.expect(isEntryLine(.bls, "options root=a"));
}
