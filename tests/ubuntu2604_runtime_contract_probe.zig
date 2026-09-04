//! Static guest probe that evaluates the Ubuntu 26.04 core runtime contract.
//!
//! Not part of any published image. `build.zig` cross-builds this per guest
//! architecture; the QEMU acceptance test and the Azure acceptance script both
//! push the resulting static binary into the running guest over SSH and run it
//! there.
//!
//! Its reason for existing is the second half of issue #677 step 2: acceptance
//! used to answer "is BinderFS mounted", "is Secure Boot on", and "is the
//! trust store real" by running `findmnt`, `od`, `grep`, `cat`, and
//! `mountpoint` inside the guest. Every one of those is a package the image
//! would then have to keep purely so a test could pass. This probe answers the
//! same questions with syscalls only, so package minimization is never asked
//! to preserve a tool nothing in production uses.
//!
//! Usage:
//!
//!   ubuntu2604-runtime-contract-probe contract
//!       Evaluates every probeable requirement in
//!       `scripts/ubuntu2604/runtime_contract.zig` and prints one
//!       `runtime-contract id=<id> kind=<kind> status=<status> target=<...>`
//!       line each, in table order.
//!
//!   ubuntu2604-runtime-contract-probe filesystem <path>...
//!       Prints one `filesystem path=<path> block_size=... total_blocks=...
//!       free_blocks=... total_inodes=... free_inodes=...` line per path, which
//!       is the ext4 accounting the size inventory's `first_boot` phase needs
//!       and which no shell utility in the final guest is required to provide.
//!
//! Exit status is 0 whenever the requested report was produced, even when
//! requirements failed: the caller decides pass or fail by verifying the
//! report, so one failing requirement never hides the diagnostics for the
//! rest. Exit status 2 means the command line itself was wrong.

const std = @import("std");
const linux = std.os.linux;

const contract = @import("ubuntu2604_runtime_contract");

const Status = contract.Status;

/// Path buffer size. Every contract target is far shorter than this; the
/// bound exists so the probe never allocates.
const path_max = 512;

var output_buffer: [64 * 1024]u8 = undefined;
var output_len: usize = 0;

fn emit(comptime fmt: []const u8, args: anytype) void {
    const remaining = output_buffer[output_len..];
    const written = std.fmt.bufPrint(remaining, fmt, args) catch return;
    output_len += written.len;
}

fn flush() void {
    var offset: usize = 0;
    while (offset < output_len) {
        const rc = linux.write(1, output_buffer[offset..].ptr, output_len - offset);
        const err = linux.errno(rc);
        if (err != .SUCCESS) return;
        if (rc == 0) return;
        offset += rc;
    }
}

// ---------------------------------------------------------------------------
// Syscall helpers. Nothing here touches libc or the general-purpose allocator.
// ---------------------------------------------------------------------------

/// Copies `path` into a NUL-terminated stack buffer, because every syscall
/// below needs a C string and the contract holds Zig slices.
fn terminate(buffer: *[path_max]u8, path: []const u8) ?[*:0]const u8 {
    if (path.len >= buffer.len) return null;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    return @ptrCast(buffer);
}

const FileKind = enum { regular, directory, symlink, character_device, other };

fn kindOf(mode: u16) FileKind {
    return switch (mode & linux.S.IFMT) {
        linux.S.IFREG => .regular,
        linux.S.IFDIR => .directory,
        linux.S.IFLNK => .symlink,
        linux.S.IFCHR => .character_device,
        else => .other,
    };
}

/// `statx` is the one stat entry point every 64-bit Linux architecture this
/// image targets exposes directly, so using it avoids an architecture-specific
/// `stat` structure layout.
fn statKind(path: []const u8, follow: bool) ?FileKind {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return null;
    var result: linux.Statx = undefined;
    const flags: u32 = if (follow) 0 else linux.AT.SYMLINK_NOFOLLOW;
    const rc = linux.statx(
        linux.AT.FDCWD,
        c_path,
        flags,
        .{ .TYPE = true, .MODE = true },
        &result,
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return kindOf(result.mode);
}

const access_x_ok: u32 = 1;
const access_w_ok: u32 = 2;
const access_r_ok: u32 = 4;

fn accessible(path: []const u8, mode: u32) bool {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return false;
    return linux.errno(linux.faccessat(linux.AT.FDCWD, c_path, mode, 0)) == .SUCCESS;
}

fn readLinkInto(path: []const u8, out: []u8) ?[]const u8 {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return null;
    const rc = linux.readlinkat(linux.AT.FDCWD, c_path, out.ptr, out.len);
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc >= out.len) return null;
    return out[0..rc];
}

/// Reads at most `out.len` bytes of `path`. Contract markers all live in the
/// first few kilobytes of the files that carry them, so a bounded read is both
/// sufficient and immune to a pathological file.
fn readInto(path: []const u8, out: []u8) ?[]const u8 {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return null;
    const open_rc = linux.open(c_path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(open_rc);
    defer _ = linux.close(fd);
    var filled: usize = 0;
    while (filled < out.len) {
        const rc = linux.read(fd, out[filled..].ptr, out.len - filled);
        if (linux.errno(rc) != .SUCCESS) return null;
        if (rc == 0) break;
        filled += rc;
    }
    return out[0..filled];
}

/// Mounts `fstype` at `dir` when it is not already there. Secure Boot state
/// and the lockdown mode both live behind filesystems a minimal appliance has
/// no reason to keep mounted, and the shell version of this check reached for
/// `mount(8)` to expose them. Doing it here is what lets the image drop that
/// dependency.
fn mountIfNeeded(dir: []const u8, fstype: []const u8) void {
    var dir_buffer: [path_max]u8 = undefined;
    var type_buffer: [path_max]u8 = undefined;
    const c_dir = terminate(&dir_buffer, dir) orelse return;
    const c_type = terminate(&type_buffer, fstype) orelse return;
    _ = linux.mount(c_type, c_dir, c_type, 0, 0);
}

// ---------------------------------------------------------------------------
// /proc/mounts.
// ---------------------------------------------------------------------------

var mounts_buffer: [256 * 1024]u8 = undefined;
var mounts: []const u8 = &.{};

fn loadMounts() void {
    mounts = readInto("/proc/mounts", &mounts_buffer) orelse &.{};
}

/// The filesystem type currently mounted at `mount_point`, or null.
///
/// `/proc/mounts` lists mounts in mount order and a later line shadows an
/// earlier one at the same point, so the last match is the live filesystem.
fn mountedFilesystem(mount_point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ' ');
        _ = fields.next() orelse continue;
        const point = fields.next() orelse continue;
        const fstype = fields.next() orelse continue;
        if (std.mem.eql(u8, point, mount_point)) found = fstype;
    }
    return found;
}

// ---------------------------------------------------------------------------
// Per-kind evaluation.
// ---------------------------------------------------------------------------

fn evaluatePath(target: []const u8, expected: FileKind) Status {
    const kind = statKind(target, true) orelse return .missing;
    if (kind != expected) return .wrong_type;
    return .ok;
}

fn evaluateCommand(target: []const u8) Status {
    const status = evaluatePath(target, .regular);
    if (status != .ok) return status;
    if (!accessible(target, access_x_ok)) return .not_executable;
    return .ok;
}

fn evaluateDevice(target: []const u8) Status {
    const status = evaluatePath(target, .character_device);
    if (status != .ok) return status;
    if (!accessible(target, access_r_ok)) return .not_readable;
    if (!accessible(target, access_w_ok)) return .not_writable;
    return .ok;
}

fn evaluateSymlink(target: []const u8, expected: []const u8) Status {
    const kind = statKind(target, false) orelse return .missing;
    if (kind != .symlink) return .wrong_type;
    var buffer: [path_max]u8 = undefined;
    const link = readLinkInto(target, &buffer) orelse return .unreadable;
    if (!std.mem.eql(u8, link, expected)) return .wrong_target;
    return .ok;
}

var marker_buffer: [512 * 1024]u8 = undefined;

fn evaluateMarker(target: []const u8, marker: []const u8) Status {
    const kind = statKind(target, true) orelse return .missing;
    if (kind != .regular) return .wrong_type;
    const contents = readInto(target, &marker_buffer) orelse return .unreadable;
    if (std.mem.indexOf(u8, contents, marker) == null) return .marker_absent;
    return .ok;
}

fn evaluateModule(name: []const u8) Status {
    var path_buffer: [path_max]u8 = undefined;
    const module_dir = std.fmt.bufPrint(&path_buffer, "/sys/module/{s}", .{name}) catch
        return .unreadable;
    const kind = statKind(module_dir, true) orelse return .missing;
    if (kind != .directory) return .wrong_type;

    var taint_path_buffer: [path_max]u8 = undefined;
    const taint_path = std.fmt.bufPrint(
        &taint_path_buffer,
        "/sys/module/{s}/taint",
        .{name},
    ) catch return .unreadable;
    var taint_buffer: [64]u8 = undefined;
    const taint = readInto(taint_path, &taint_buffer) orelse return .ok;
    const trimmed = std.mem.trim(u8, taint, " \t\r\n");
    if (trimmed.len != 0) return .tainted;
    return .ok;
}

fn evaluateMount(mount_point: []const u8, expected: []const u8) Status {
    const fstype = mountedFilesystem(mount_point) orelse return .not_mounted;
    if (!std.mem.eql(u8, fstype, expected)) return .wrong_filesystem;
    return .ok;
}

fn evaluatePid1(expected: []const u8) Status {
    var buffer: [path_max]u8 = undefined;
    const link = readLinkInto("/proc/1/exe", &buffer) orelse return .unreadable;
    // A replaced-on-disk PID 1 keeps running and the kernel appends this
    // marker; the identity is still the one being asserted.
    const deleted = " (deleted)";
    const resolved = if (std.mem.endsWith(u8, link, deleted))
        link[0 .. link.len - deleted.len]
    else
        link;
    if (std.mem.eql(u8, resolved, expected)) return .ok;
    // `/sbin` and `/bin` are usr-merge symlinks, so the kernel may report
    // either spelling depending on how PID 1 was named on the command line.
    // Both denote the same program; only a different program is a failure.
    if (mergedUsrAlias(expected)) |alias| {
        if (std.mem.eql(u8, resolved, alias)) return .ok;
    }
    return .wrong_target;
}

/// The pre-usr-merge spelling of a `/usr`-prefixed path, or null when the path
/// has no such alias.
fn mergedUsrAlias(path: []const u8) ?[]const u8 {
    const prefixes = [_][]const u8{ "/usr/sbin/", "/usr/bin/" };
    inline for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) {
            return path["/usr".len..];
        }
    }
    return null;
}

/// The EFI global variable GUID, which is fixed by the UEFI specification, so
/// the exact `SecureBoot` variable path is known without listing a directory.
const secure_boot_variable = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn evaluateSecureBoot(efivars_dir: []const u8) Status {
    var path_buffer: [path_max]u8 = undefined;
    const path = std.fmt.bufPrint(
        &path_buffer,
        "{s}/{s}",
        .{ efivars_dir, secure_boot_variable },
    ) catch return .unreadable;
    var value: [8]u8 = undefined;
    var contents = readInto(path, &value);
    if (contents == null) {
        mountIfNeeded(efivars_dir, "efivarfs");
        contents = readInto(path, &value);
    }
    const bytes = contents orelse return .unreadable;
    // An efivarfs variable is four attribute bytes followed by its data.
    if (bytes.len < 5) return .unreadable;
    if (bytes[4] != 1) return .disabled;
    return .ok;
}

fn evaluateLockdown(path: []const u8) Status {
    var value: [256]u8 = undefined;
    var contents = readInto(path, &value);
    if (contents == null) {
        mountIfNeeded("/sys/kernel/security", "securityfs");
        contents = readInto(path, &value);
    }
    const bytes = contents orelse return .unreadable;
    if (std.mem.indexOf(u8, bytes, "[integrity]") != null) return .ok;
    if (std.mem.indexOf(u8, bytes, "[confidentiality]") != null) return .ok;
    return .disabled;
}

fn evaluate(requirement: contract.Requirement) Status {
    return switch (requirement.kind) {
        .package => .ok,
        .command => evaluateCommand(requirement.target),
        .file => evaluatePath(requirement.target, .regular),
        .directory, .mutable_path => evaluatePath(requirement.target, .directory),
        .symlink => evaluateSymlink(requirement.target, requirement.expect),
        .config, .trust_store => evaluateMarker(requirement.target, requirement.expect),
        .kernel_module => evaluateModule(requirement.target),
        .device => evaluateDevice(requirement.target),
        .mount => evaluateMount(requirement.target, requirement.expect),
        .pid1 => evaluatePid1(requirement.target),
        .secure_boot => evaluateSecureBoot(requirement.target),
        .kernel_lockdown => evaluateLockdown(requirement.target),
    };
}

fn reportContract() void {
    loadMounts();
    for (contract.requirements()) |requirement| {
        if (!requirement.kind.probeable()) continue;
        const status = evaluate(requirement);
        emit("{s} id={s} kind={s} audience={s} status={s} target={s}\n", .{
            contract.report_prefix,
            requirement.id,
            requirement.kind.key(),
            requirement.audience.key(),
            status.key(),
            requirement.target,
        });
    }
}

// ---------------------------------------------------------------------------
// Filesystem accounting.
// ---------------------------------------------------------------------------

/// `struct statfs` as the kernel defines it for 64-bit architectures, which is
/// the same layout on both guest targets this probe is built for: eleven
/// 64-bit words followed by four spare ones.
const Statfs = extern struct {
    type: u64,
    bsize: u64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]u32,
    namelen: u64,
    frsize: u64,
    flags: u64,
    spare: [4]u64,
};

fn reportFilesystem(path: []const u8) bool {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return false;
    var result: Statfs = undefined;
    const rc = linux.syscall2(
        .statfs,
        @intFromPtr(c_path),
        @intFromPtr(&result),
    );
    if (linux.errno(rc) != .SUCCESS) {
        emit("{s} path={s} status=unreadable\n", .{ contract.filesystem_prefix, path });
        return false;
    }
    emit(
        "{s} path={s} block_size={d} total_blocks={d} free_blocks={d} " ++
            "total_inodes={d} free_inodes={d}\n",
        .{
            contract.filesystem_prefix,
            path,
            result.bsize,
            result.blocks,
            result.bfree,
            result.files,
            result.ffree,
        },
    );
    return true;
}

pub fn main(init: std.process.Init.Minimal) u8 {
    const args = init.args.vector;
    if (args.len < 2) {
        emit(
            "usage: ubuntu2604-runtime-contract-probe (contract | filesystem <path>...)\n",
            .{},
        );
        flush();
        return 2;
    }
    const command = std.mem.span(args[1]);
    if (std.mem.eql(u8, command, "contract")) {
        if (args.len != 2) {
            emit("usage: ubuntu2604-runtime-contract-probe contract\n", .{});
            flush();
            return 2;
        }
        reportContract();
        flush();
        return 0;
    }
    if (std.mem.eql(u8, command, "filesystem")) {
        if (args.len < 3) {
            emit("usage: ubuntu2604-runtime-contract-probe filesystem <path>...\n", .{});
            flush();
            return 2;
        }
        var complete = true;
        for (args[2..]) |argument| {
            if (!reportFilesystem(std.mem.span(argument))) complete = false;
        }
        flush();
        return if (complete) 0 else 1;
    }
    emit(
        "usage: ubuntu2604-runtime-contract-probe (contract | filesystem <path>...)\n",
        .{},
    );
    flush();
    return 2;
}
