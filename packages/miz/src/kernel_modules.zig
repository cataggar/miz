//! Reading a kernel's own module tree: what it built in, what it ships as a
//! module, and in what order those modules have to be inserted.
//!
//! The `vm` backend boots the image's own kernel with `rdinit=`, so nothing
//! that would normally load a module ever runs. A driver the guest needs is
//! therefore either compiled into that kernel or inserted by the guest agent
//! from the image's own `lib/modules/<release>` tree — and inserting the
//! image's own modules is correct by construction rather than a workaround,
//! since they are the modules that kernel shipped with, so vermagic matches and
//! distro module signatures verify.
//!
//! This module deals only in bytes: `modules.builtin` and `modules.dep` come in
//! as slices and dependency-ordered paths come out. Reading them out of an
//! image is `vm_payload`'s job, and it is the only caller that has an ext4
//! reader. Keeping the parsing separate is what lets every rule below be tested
//! without building a filesystem.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    /// A module the run needs is neither built in nor present in the tree,
    /// which is a refusal rather than a guess: a driver that never loads is a
    /// device that never appears, and the guest can only report that as a
    /// timeout.
    ModuleNotInTree,
    ModuleDependencyCycle,
    ModuleDependencyTooDeep,
    /// A compression format the host cannot read. Refused rather than shipped,
    /// because the guest cannot read it either unless the target kernel sets
    /// `CONFIG_MODULE_DECOMPRESS`, which is not something an image promises.
    UnsupportedModuleCompression,
    ModuleDecompressionFailed,
    ModuleTooLarge,
    /// The decompressed bytes are not an ELF object, so whatever the tree
    /// holds at that path, it is not a module the guest could load.
    ModuleNotAnObject,
};

/// Ceiling on a single decompressed module. Generous next to the drivers this
/// backend needs — the whole `ext4` closure is on the order of a megabyte —
/// and low enough that a malformed tree cannot exhaust the host.
pub const max_module_bytes: usize = 32 * 1024 * 1024;

/// Depth of the dependency walk. Real closures are a handful deep; a limit
/// keeps a malformed `modules.dep` from recursing as far as it likes.
pub const max_dependency_depth: usize = 64;

/// The name the kernel knows a module file by: `virtio_blk` for
/// `kernel/drivers/block/virtio_blk.ko.xz`.
pub fn moduleName(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    const index = std.mem.lastIndexOf(u8, base, ".ko") orelse return base;
    const after = base[index + ".ko".len ..];
    if (after.len == 0 or after[0] == '.') return base[0..index];
    return base;
}

/// Module names compare with `-` and `_` equivalent, the way modprobe treats
/// them: `crc-itu-t.ko` is the module `crc_itu_t`.
pub fn namesEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (normalize(a) != normalize(b)) return false;
    }
    return true;
}

fn normalize(byte: u8) u8 {
    return if (byte == '-') '_' else byte;
}

/// Whether `modules.builtin` claims `name` is compiled into the kernel.
///
/// `modules.builtin` holds one module path per line, e.g.
/// `kernel/drivers/scsi/virtio_scsi.ko`. Comparing whole names keeps
/// `virtio_blk` from matching a differently-named module that merely starts
/// with those characters.
pub fn isBuiltIn(listing: []const u8, name: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, listing, "\r\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) continue;
        if (namesEqual(moduleName(trimmed), name)) return true;
    }
    return false;
}

/// A parsed `modules.dep`.
///
/// Every path it hands back is a slice of the caller's bytes, so the source
/// must outlive it. That keeps a file with thousands of lines to one
/// allocation for the index rather than one per module.
pub const Dependencies = struct {
    entries: []const Entry,

    pub const Entry = struct {
        /// Path relative to `lib/modules/<release>`, e.g.
        /// `kernel/fs/ext4/ext4.ko.xz`.
        path: []const u8,
        /// The rest of the line: the paths this module depends on, unsplit.
        dependencies: []const u8,
    };

    /// Lines are `<module path>: <dependency path>...`, with dependencies
    /// separated by spaces and absent entirely for a module that has none.
    pub fn parse(allocator: Allocator, bytes: []const u8) Allocator.Error!Dependencies {
        var entries: std.array_list.Managed(Entry) = .init(allocator);
        errdefer entries.deinit();

        var lines = std.mem.tokenizeAny(u8, bytes, "\r\n");
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const path = trimPath(line[0..colon]);
            if (path.len == 0) continue;
            try entries.append(.{
                .path = path,
                .dependencies = std.mem.trim(u8, line[colon + 1 ..], " \t"),
            });
        }
        return .{ .entries = try entries.toOwnedSlice() };
    }

    pub fn deinit(self: Dependencies, allocator: Allocator) void {
        allocator.free(self.entries);
    }

    pub fn indexOfName(self: Dependencies, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, index| {
            if (namesEqual(moduleName(entry.path), name)) return index;
        }
        return null;
    }

    pub fn indexOfPath(self: Dependencies, path: []const u8) ?usize {
        const wanted = trimPath(path);
        for (self.entries, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.path, wanted)) return index;
        }
        return null;
    }

    /// The modules that have to be inserted for `requested` to be usable, in
    /// insertion order: every dependency before the module that needs it, each
    /// module once, and requested modules in the caller's own order so that an
    /// identical run resolves an identical list.
    ///
    /// A requested module the kernel already builds in contributes nothing —
    /// it is already there — which is what makes "built in, or loadable, or
    /// refuse" a single pass rather than two policies.
    pub fn resolve(
        self: Dependencies,
        allocator: Allocator,
        builtin_listing: []const u8,
        requested: []const []const u8,
    ) (Allocator.Error || Error)![]const []const u8 {
        const states = try allocator.alloc(Visit, self.entries.len);
        defer allocator.free(states);
        @memset(states, .unvisited);

        var order: std.array_list.Managed([]const u8) = .init(allocator);
        errdefer order.deinit();

        for (requested) |name| {
            if (isBuiltIn(builtin_listing, name)) continue;
            const index = self.indexOfName(name) orelse return error.ModuleNotInTree;
            try self.visit(index, states, &order, 0);
        }
        return order.toOwnedSlice();
    }

    const Visit = enum { unvisited, in_progress, emitted };

    fn visit(
        self: Dependencies,
        index: usize,
        states: []Visit,
        order: *std.array_list.Managed([]const u8),
        depth: usize,
    ) (Allocator.Error || Error)!void {
        switch (states[index]) {
            .emitted => return,
            .in_progress => return error.ModuleDependencyCycle,
            .unvisited => {},
        }
        if (depth >= max_dependency_depth) return error.ModuleDependencyTooDeep;
        states[index] = .in_progress;

        var dependencies = std.mem.tokenizeAny(u8, self.entries[index].dependencies, " \t");
        while (dependencies.next()) |dependency| {
            const dependency_index = self.indexOfPath(dependency) orelse
                return error.ModuleNotInTree;
            try self.visit(dependency_index, states, order, depth + 1);
        }

        states[index] = .emitted;
        try order.append(self.entries[index].path);
    }
};

/// `modules.dep` paths are relative to the module directory. Some generators
/// write them with a leading slash, which names the same file.
fn trimPath(path: []const u8) []const u8 {
    return std.mem.trimStart(u8, std.mem.trim(u8, path, " \t"), "/");
}

/// How a module file is stored. The kernel's own `CONFIG_MODULE_COMPRESS_*`
/// options produce exactly these.
pub const Compression = enum { none, gzip, xz, zstd };

/// `null` for a suffix this cannot read, which is a refusal rather than a
/// silent skip.
pub fn compressionOf(path: []const u8) ?Compression {
    const base = std.fs.path.basename(path);
    if (std.mem.endsWith(u8, base, ".ko")) return .none;
    if (std.mem.endsWith(u8, base, ".ko.xz")) return .xz;
    if (std.mem.endsWith(u8, base, ".ko.zst")) return .zstd;
    if (std.mem.endsWith(u8, base, ".ko.gz")) return .gzip;
    return null;
}

/// The loadable bytes of a module stored at `path`.
///
/// Decompression happens here, on the host, rather than in the guest: the
/// guest can only decompress a module itself if its kernel sets
/// `CONFIG_MODULE_DECOMPRESS`, and an image makes no such promise. The host
/// reading the format is checkable before boot; the guest failing to is a
/// timeout.
pub fn moduleImage(
    allocator: Allocator,
    path: []const u8,
    stored: []const u8,
    max_bytes: usize,
) (Allocator.Error || Error)![]u8 {
    const compression = compressionOf(path) orelse return error.UnsupportedModuleCompression;
    const bytes = switch (compression) {
        .none => blk: {
            if (stored.len > max_bytes) return error.ModuleTooLarge;
            break :blk try allocator.dupe(u8, stored);
        },
        .gzip => try decompressGzip(allocator, stored, max_bytes),
        .xz => try decompressXz(allocator, stored, max_bytes),
        .zstd => try decompressZstd(allocator, stored, max_bytes),
    };
    errdefer allocator.free(bytes);
    if (!isElf(bytes)) return error.ModuleNotAnObject;
    return bytes;
}

fn isElf(bytes: []const u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF");
}

fn decompressGzip(allocator: Allocator, bytes: []const u8, max_bytes: usize) (Allocator.Error || Error)![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    return decompressor.reader.allocRemaining(allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.ModuleTooLarge,
        error.ReadFailed => error.ModuleDecompressionFailed,
    };
}

fn decompressXz(allocator: Allocator, bytes: []const u8, max_bytes: usize) (Allocator.Error || Error)![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    var decompressor = std.compress.xz.Decompress.init(&input, allocator, &.{}) catch |err| switch (err) {
        error.NotXzStream, error.WrongChecksum, error.EndOfStream, error.ReadFailed => return error.ModuleDecompressionFailed,
    };
    defer decompressor.deinit();
    return decompressor.reader.allocRemaining(allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.ModuleTooLarge,
        // An xz stream this decoder does not implement is as unreadable as a
        // format it does not know, and both have to be refusals.
        error.ReadFailed => switch (decompressor.err orelse error.ModuleDecompressionFailed) {
            error.Unsupported => error.UnsupportedModuleCompression,
            else => error.ModuleDecompressionFailed,
        },
    };
}

fn decompressZstd(allocator: Allocator, bytes: []const u8, max_bytes: usize) (Allocator.Error || Error)![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    // Indirect mode with an explicitly sized window: the direct mode requires
    // the destination to already have window-sized capacity on every read,
    // which `allocRemaining`'s growing buffer does not guarantee and which
    // silently truncated large streams when `verity_tooling.zig` relied on it.
    const window_len = std.compress.zstd.default_window_len;
    const window = try allocator.alloc(u8, window_len + std.compress.zstd.block_size_max);
    defer allocator.free(window);
    var decompressor = std.compress.zstd.Decompress.init(&input, window, .{
        .window_len = window_len,
    });
    return decompressor.reader.allocRemaining(allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.ModuleTooLarge,
        error.ReadFailed => error.ModuleDecompressionFailed,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two lines of a real Azure Linux `modules.builtin` next to the module the
/// same kernel ships as `virtio_blk.ko.xz`, which is the case that motivated
/// reading any of these files.
const azure_linux_builtin =
    \\kernel/fs/ext4/ext4.ko
    \\kernel/drivers/virtio/virtio_pci.ko
    \\kernel/drivers/scsi/scsi_mod.ko
    \\kernel/drivers/scsi/sd_mod.ko
    \\kernel/drivers/scsi/virtio_scsi.ko
    \\
;

/// The shape a distribution that modularizes its root filesystem produces:
/// `ext4` needs `mbcache`, `jbd2` and `crc32c_generic`, and `virtio_blk` needs
/// the bus driver that is built in above.
const modular_dep =
    \\kernel/fs/ext4/ext4.ko.xz: kernel/fs/mbcache.ko.xz kernel/fs/jbd2/jbd2.ko.xz kernel/crypto/crc32c_generic.ko.xz
    \\kernel/fs/mbcache.ko.xz:
    \\kernel/fs/jbd2/jbd2.ko.xz: kernel/crypto/crc32c_generic.ko.xz
    \\kernel/crypto/crc32c_generic.ko.xz:
    \\kernel/drivers/block/virtio_blk.ko.xz:
    \\kernel/drivers/scsi/virtio_scsi.ko.xz: kernel/drivers/scsi/scsi_mod.ko.xz
    \\kernel/drivers/scsi/scsi_mod.ko.xz:
    \\kernel/lib/crc-itu-t.ko.xz:
    \\
;

test "a module is named by its file, whatever it is compressed with" {
    try std.testing.expectEqualStrings("ext4", moduleName("kernel/fs/ext4/ext4.ko"));
    try std.testing.expectEqualStrings("ext4", moduleName("kernel/fs/ext4/ext4.ko.xz"));
    try std.testing.expectEqualStrings("virtio_blk", moduleName("virtio_blk.ko.zst"));
    try std.testing.expectEqualStrings("virtio_net", moduleName("virtio_net.ko.gz"));
    // A name that merely contains the letters is a different module.
    try std.testing.expectEqualStrings("virtio_blk_helper", moduleName("virtio_blk_helper.ko"));
    try std.testing.expect(!namesEqual(moduleName("virtio_blk_helper.ko"), "virtio_blk"));
    // modprobe treats the two separators as one, and so does a distribution
    // that ships `crc-itu-t.ko` for the module `crc_itu_t`.
    try std.testing.expect(namesEqual(moduleName("kernel/lib/crc-itu-t.ko.xz"), "crc_itu_t"));
}

test "modules.builtin answers only for whole module names" {
    try std.testing.expect(isBuiltIn(azure_linux_builtin, "ext4"));
    try std.testing.expect(isBuiltIn(azure_linux_builtin, "virtio_scsi"));
    try std.testing.expect(isBuiltIn(azure_linux_builtin, "sd_mod"));
    try std.testing.expect(!isBuiltIn(azure_linux_builtin, "virtio_blk"));
    try std.testing.expect(!isBuiltIn(azure_linux_builtin, "virtio"));
    try std.testing.expect(!isBuiltIn("", "ext4"));
}

test "a dependency closure is resolved in insertion order" {
    const allocator = std.testing.allocator;
    const dependencies = try Dependencies.parse(allocator, modular_dep);
    defer dependencies.deinit(allocator);

    const order = try dependencies.resolve(allocator, "", &.{ "ext4", "virtio_scsi" });
    defer allocator.free(order);

    // Every dependency precedes what needs it, each module appears once, and
    // a module reached twice is not inserted twice.
    try std.testing.expectEqual(@as(usize, 6), order.len);
    try std.testing.expectEqualStrings("kernel/fs/mbcache.ko.xz", order[0]);
    try std.testing.expectEqualStrings("kernel/crypto/crc32c_generic.ko.xz", order[1]);
    try std.testing.expectEqualStrings("kernel/fs/jbd2/jbd2.ko.xz", order[2]);
    try std.testing.expectEqualStrings("kernel/fs/ext4/ext4.ko.xz", order[3]);
    try std.testing.expectEqualStrings("kernel/drivers/scsi/scsi_mod.ko.xz", order[4]);
    try std.testing.expectEqualStrings("kernel/drivers/scsi/virtio_scsi.ko.xz", order[5]);
}

test "a module the kernel already builds in is not inserted again" {
    const allocator = std.testing.allocator;
    const dependencies = try Dependencies.parse(allocator, modular_dep);
    defer dependencies.deinit(allocator);

    const order = try dependencies.resolve(
        allocator,
        azure_linux_builtin,
        &.{ "ext4", "virtio_scsi", "virtio_blk" },
    );
    defer allocator.free(order);

    try std.testing.expectEqual(@as(usize, 1), order.len);
    try std.testing.expectEqualStrings("kernel/drivers/block/virtio_blk.ko.xz", order[0]);
}

test "a module that is neither built in nor in the tree is refused" {
    const allocator = std.testing.allocator;
    const dependencies = try Dependencies.parse(allocator, modular_dep);
    defer dependencies.deinit(allocator);

    try std.testing.expectError(
        error.ModuleNotInTree,
        dependencies.resolve(allocator, "", &.{"virtio_net"}),
    );

    // A dependency named by a line whose own file the tree does not describe
    // is the same refusal: a closure that cannot be completed is not a closure.
    const dangling = try Dependencies.parse(
        allocator,
        "kernel/fs/ext4/ext4.ko.xz: kernel/fs/jbd2/jbd2.ko.xz\n",
    );
    defer dangling.deinit(allocator);
    try std.testing.expectError(
        error.ModuleNotInTree,
        dangling.resolve(allocator, "", &.{"ext4"}),
    );
}

test "a circular modules.dep is refused rather than walked forever" {
    const allocator = std.testing.allocator;
    const dependencies = try Dependencies.parse(allocator, "a.ko: b.ko\nb.ko: a.ko\n");
    defer dependencies.deinit(allocator);

    try std.testing.expectError(
        error.ModuleDependencyCycle,
        dependencies.resolve(allocator, "", &.{"a"}),
    );
}

test "dependency paths are read whether or not they are written with a leading slash" {
    const allocator = std.testing.allocator;
    const dependencies = try Dependencies.parse(
        allocator,
        "/kernel/fs/ext4/ext4.ko.xz: /kernel/fs/jbd2/jbd2.ko.xz\n/kernel/fs/jbd2/jbd2.ko.xz:\n",
    );
    defer dependencies.deinit(allocator);

    const order = try dependencies.resolve(allocator, "", &.{"ext4"});
    defer allocator.free(order);
    try std.testing.expectEqual(@as(usize, 2), order.len);
    try std.testing.expectEqualStrings("kernel/fs/jbd2/jbd2.ko.xz", order[0]);
    try std.testing.expectEqualStrings("kernel/fs/ext4/ext4.ko.xz", order[1]);
}

/// A minimal ELF header, which is all `moduleImage` checks for: it is looking
/// for evidence that the tree holds an object, not parsing one.
const elf_object = "\x7fELF" ++ "\x02\x01\x01" ++ ("\x00" ** 57);

test "an uncompressed module is passed through and a foreign file is not" {
    const allocator = std.testing.allocator;
    const bytes = try moduleImage(allocator, "kernel/fs/ext4/ext4.ko", elf_object, max_module_bytes);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(elf_object, bytes);

    try std.testing.expectError(error.ModuleNotAnObject, moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko",
        "#!/bin/sh\n",
        max_module_bytes,
    ));
    try std.testing.expectError(error.ModuleTooLarge, moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko",
        elf_object,
        4,
    ));
}

test "a compression format the host cannot read is refused rather than shipped" {
    const allocator = std.testing.allocator;
    try std.testing.expect(compressionOf("ext4.ko.lz4") == null);
    try std.testing.expect(compressionOf("ext4.ko.bz2") == null);
    try std.testing.expectEqual(Compression.zstd, compressionOf("ext4.ko.zst").?);

    try std.testing.expectError(error.UnsupportedModuleCompression, moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko.lz4",
        elf_object,
        max_module_bytes,
    ));
}

test "a gzip-compressed module is decompressed host-side" {
    const allocator = std.testing.allocator;
    var compressed: std.Io.Writer.Allocating = try .initCapacity(allocator, 1024);
    defer compressed.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &compressed.writer,
        &history,
        .gzip,
        .default,
    );
    try compressor.writer.writeAll(elf_object);
    try compressor.finish();

    const bytes = try moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko.gz",
        compressed.written(),
        max_module_bytes,
    );
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(elf_object, bytes);
}

test "a zstd-compressed module is decompressed host-side" {
    const allocator = std.testing.allocator;
    const zstd = @import("zstd.zig");
    var compressed: std.Io.Writer.Allocating = try .initCapacity(allocator, 1024);
    defer compressed.deinit();
    try zstd.writeRawFrameForSlice(&compressed.writer, elf_object, null);

    const bytes = try moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko.zst",
        compressed.written(),
        max_module_bytes,
    );
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(elf_object, bytes);
}

test "an xz-compressed module is decompressed host-side" {
    const allocator = std.testing.allocator;
    // xz is what Azure Linux, Fedora and Debian actually ship modules in, so
    // it is the format that matters most here. Nothing in this project writes
    // xz, so the fixture comes from the in-tree test encoder, which keeps this
    // coverage unconditional instead of dependent on host tooling.
    const xz_fixture = @import("xz_fixture.zig");
    const compressed = try xz_fixture.allocStream(allocator, elf_object, .{});
    defer allocator.free(compressed);

    const bytes = try moduleImage(
        allocator,
        "kernel/fs/ext4/ext4.ko.xz",
        compressed,
        max_module_bytes,
    );
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(elf_object, bytes);
}
