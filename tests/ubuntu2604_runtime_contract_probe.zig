//! Static guest probe that evaluates the Ubuntu 26.04 core runtime contract.
//!
//! Not part of any published image. `build.zig` cross-builds this per guest
//! architecture; the QEMU acceptance test and the Azure acceptance script both
//! push the resulting static binary into the running guest over SSH and run it
//! there.
//!
//! Its reason for existing is the second half of issue #677 step 2: acceptance
//! used to answer "is BinderFS mounted", "is Secure Boot on", "is the UEFI
//! signature database real", and "is the trust store real" by running
//! `findmnt`, `od`, `grep`, `cat`, `mountpoint`, and `mount` inside the guest.
//! Every one of those is a package the image would then have to keep purely so
//! a test could pass -- `mount` is util-linux, which the minimized core closure
//! does not install at all. This probe answers the same questions with
//! syscalls only, so package minimization is never asked to preserve a tool
//! nothing in production uses.
//!
//! Usage:
//!
//!   ubuntu2604-runtime-contract-probe contract
//!       Evaluates every probeable requirement in
//!       `scripts/ubuntu2604/runtime_contract.zig` and prints one
//!       `runtime-contract id=<id> kind=<kind> status=<status> target=<...>`
//!       line each, in table order.
//!
//!   ubuntu2604-runtime-contract-probe requirement <id>...
//!       Evaluates only the named requirements, in the same line format. The
//!       full contract is the core appliance's; Secure Boot and kernel
//!       lockdown are platform facts every flavor is held to, so acceptance
//!       asks for those by name on full and bare-metal candidates too.
//!
//!   ubuntu2604-runtime-contract-probe efivar <name>...
//!       Mounts efivarfs if nothing else already has, prints one
//!       `efivar name=<name> status=<status> mount=<...> attributes=0x...
//!       bytes=<n> data=<hex>` line per variable, and unmounts only what it
//!       mounted. This is how acceptance obtains the UEFI signature database
//!       to look for the release signing certificate in, without a `mount(8)`
//!       in the guest.
//!
//!   ubuntu2604-runtime-contract-probe filesystem <path>...
//!       Prints one `filesystem path=<path> block_size=... total_blocks=...
//!       free_blocks=... total_inodes=... free_inodes=...` line per path, which
//!       is the ext4 accounting the size inventory's `first_boot` phase needs
//!       and which no shell utility in the final guest is required to provide.
//!
//! `contract` exits 0 whenever the requested report was produced, even when
//! requirements failed: the caller decides pass or fail by verifying the
//! report, so one failing requirement never hides the diagnostics for the
//! rest. `requirement`, `efivar`, and `filesystem` exit non-zero when a
//! requested item could not be reported at all, and every one of them exits 2
//! when the command line itself was wrong.

const std = @import("std");
const linux = std.os.linux;

const contract = @import("ubuntu2604_runtime_contract");

const Status = contract.Status;

/// Path buffer size. Every contract target is far shorter than this; the
/// bound exists so the probe never allocates.
const path_max = 512;

/// Report buffer. It has to hold the hex of the largest UEFI variable the
/// probe will report (`efivar_max_bytes`, doubled) plus the surrounding lines,
/// because a report is written whole and flushed once.
var output_buffer: [128 * 1024]u8 = undefined;
var output_len: usize = 0;
/// Set when a line did not fit. A truncated report is a failed report: the
/// caller must never read a cut-off signature database as the whole one.
var output_truncated = false;

fn emit(comptime fmt: []const u8, args: anytype) void {
    const remaining = output_buffer[output_len..];
    const written = std.fmt.bufPrint(remaining, fmt, args) catch {
        output_truncated = true;
        return;
    };
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

/// Establishes `fstype` somewhere readable and reports where.
///
/// Secure Boot state, the UEFI signature database, and the lockdown mode all
/// live behind filesystems a minimal appliance has no reason to keep mounted,
/// and the shell version of these checks reached for `mount(8)` to expose
/// them. Doing it here with `mount(2)` is what lets the image drop that
/// dependency: `mount` is util-linux, and #677 forbids retaining a package
/// because a test used it.
///
/// The conventional mount point wins when it already carries the right
/// filesystem, so the common case observes rather than acts. Otherwise the
/// probe mounts its own deterministic directory under `/run` and unmounts it
/// again, which leaves the guest's view of `/sys` exactly as the probe found
/// it and guarantees the probe only ever tears down its own mount.
const Mounted = struct {
    dir: []const u8,
    mount: contract.EfivarMount,
    /// The filesystem type found where the expected one should have been.
    found: []const u8 = "",
    status: ?contract.EfivarStatus = null,

    fn failed(status: contract.EfivarStatus, found: []const u8) Mounted {
        return .{ .dir = "", .mount = .none, .found = found, .status = status };
    }
};

fn makeDirectory(path: []const u8) bool {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return false;
    const rc = linux.mkdirat(linux.AT.FDCWD, c_path, 0o700);
    return switch (linux.errno(rc)) {
        .SUCCESS, .EXIST => true,
        else => false,
    };
}

fn removeDirectory(path: []const u8) bool {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return false;
    const rc = linux.unlinkat(linux.AT.FDCWD, c_path, linux.AT.REMOVEDIR);
    return linux.errno(rc) == .SUCCESS;
}

/// Mounts `fstype` on `dir`, distinguishing "not permitted" from "not
/// available" because the two call for different operator responses.
fn mountAt(dir: []const u8, fstype: []const u8) ?contract.EfivarStatus {
    var dir_buffer: [path_max]u8 = undefined;
    var type_buffer: [path_max]u8 = undefined;
    const c_dir = terminate(&dir_buffer, dir) orelse return .not_mounted;
    const c_type = terminate(&type_buffer, fstype) orelse return .not_mounted;
    const rc = linux.mount(c_type, c_dir, c_type, 0, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => null,
        .PERM, .ACCES => .permission_denied,
        // Another mounter winning the race to the same directory still leaves
        // the filesystem present; the type check below confirms it.
        .BUSY => null,
        else => .not_mounted,
    };
}

fn acquire(conventional: []const u8, private: []const u8, fstype: []const u8) Mounted {
    loadMounts();
    if (mountedFilesystem(conventional)) |found| {
        if (std.mem.eql(u8, found, fstype))
            return .{ .dir = conventional, .mount = .existing };
        return Mounted.failed(.wrong_filesystem, found);
    }
    if (mountedFilesystem(private)) |found| {
        // A previous run killed between mount and unmount left this behind;
        // adopting it keeps the check idempotent instead of failing on the
        // probe's own litter.
        if (std.mem.eql(u8, found, fstype))
            return .{ .dir = private, .mount = .probe };
        return Mounted.failed(.wrong_filesystem, found);
    }
    if (!makeDirectory(private)) return Mounted.failed(.not_mounted, "");
    if (mountAt(private, fstype)) |status| {
        _ = removeDirectory(private);
        return Mounted.failed(status, "");
    }
    // Trust the kernel's own answer rather than the return code: a mount that
    // succeeded while carrying some other type would otherwise be read as the
    // filesystem this check is about.
    loadMounts();
    const established: Mounted = .{ .dir = private, .mount = .probe };
    const found = mountedFilesystem(private) orelse {
        release(established);
        return Mounted.failed(.not_mounted, "");
    };
    if (!std.mem.eql(u8, found, fstype)) {
        release(established);
        return Mounted.failed(.wrong_filesystem, found);
    }
    return established;
}

/// Undoes exactly what `acquire` did, and nothing else.
fn release(mounted: Mounted) void {
    if (mounted.mount != .probe) return;
    var buffer: [path_max]u8 = undefined;
    const c_dir = terminate(&buffer, mounted.dir) orelse return;
    _ = linux.umount2(c_dir, 0);
    _ = removeDirectory(mounted.dir);
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
    return mountedFilesystemIn(mounts, mount_point);
}

/// Pure form of the above, so the shadowing rule is testable on the host
/// without a guest and without a real `/proc/mounts`.
fn mountedFilesystemIn(table: []const u8, mount_point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, table, '\n');
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
const secure_boot_variable = contract.secure_boot_variable;

/// The probe's own securityfs mount point, chosen the same way and for the
/// same reason as `contract.efivars_private_mount_point`.
const securityfs_private_mount_point = "/run/miz-securityfs";

fn evaluateSecureBoot(efivars_dir: []const u8) Status {
    const mounted = acquire(
        efivars_dir,
        contract.efivars_private_mount_point,
        contract.efivars_filesystem,
    );
    defer release(mounted);
    if (mounted.status) |status| return switch (status) {
        .wrong_filesystem => .wrong_filesystem,
        else => .not_mounted,
    };
    var path_buffer: [path_max]u8 = undefined;
    const path = std.fmt.bufPrint(
        &path_buffer,
        "{s}/{s}",
        .{ mounted.dir, secure_boot_variable },
    ) catch return .unreadable;
    var value: [8]u8 = undefined;
    const bytes = readInto(path, &value) orelse return .unreadable;
    // An efivarfs variable is four attribute bytes followed by its data.
    if (bytes.len < 5) return .unreadable;
    if (bytes[4] != 1) return .disabled;
    return .ok;
}

/// The directory `path` lives in, which is the mount point the lockdown file
/// is exposed through.
fn parentOf(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    if (slash == 0) return "/";
    return path[0..slash];
}

fn evaluateLockdown(path: []const u8) Status {
    const conventional = parentOf(path);
    const mounted = acquire(
        conventional,
        securityfs_private_mount_point,
        "securityfs",
    );
    defer release(mounted);
    if (mounted.status) |status| return switch (status) {
        .wrong_filesystem => .wrong_filesystem,
        else => .not_mounted,
    };
    var path_buffer: [path_max]u8 = undefined;
    const resolved = std.fmt.bufPrint(
        &path_buffer,
        "{s}{s}",
        .{ mounted.dir, path[conventional.len..] },
    ) catch return .unreadable;
    var value: [256]u8 = undefined;
    const bytes = readInto(resolved, &value) orelse return .unreadable;
    if (std.mem.indexOf(u8, bytes, "[integrity]") != null) return .ok;
    if (std.mem.indexOf(u8, bytes, "[confidentiality]") != null) return .ok;
    return .disabled;
}

fn evaluate(requirement: contract.Requirement) Status {
    return switch (requirement.kind) {
        // Neither is observable from inside the guest: a package is a dpkg
        // fact the shipped exact lock carries, and a selector names a
        // metapackage the build resolved and deliberately never installed.
        // `Kind.probeable` filters both out before this is reached, so the
        // arms exist to keep the switch exhaustive rather than to report.
        .package, .package_selector => .ok,
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

/// Reports the named requirements only.
///
/// The full `contract` report is core-only, because the table is the core
/// appliance's contract. Secure Boot and kernel lockdown are platform facts
/// every flavor is held to, and acceptance checks them on full and bare-metal
/// candidates too, so they are addressable one at a time in exactly the same
/// wire format the full report uses.
fn reportRequirements(ids: []const [*:0]const u8) bool {
    loadMounts();
    var complete = true;
    for (ids) |raw| {
        const id = std.mem.span(raw);
        const requirement = contract.lookup(id) orelse {
            emit("unknown requirement {s}\n", .{id});
            complete = false;
            continue;
        };
        if (!requirement.kind.probeable()) {
            emit("unprobeable requirement {s}\n", .{id});
            complete = false;
            continue;
        }
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
    return complete;
}

// ---------------------------------------------------------------------------
// UEFI variables.
//
// Acceptance asks the guest for the signature database itself, not just for a
// verdict about it, because the certificate the release was signed with has to
// be found inside it on the host. The shell version of that read was
// `mount -t efivarfs` followed by `cat`, and `mount` is util-linux: a package
// the minimized core closure does not install and must not be made to install
// so a test can pass.
// ---------------------------------------------------------------------------

/// The largest UEFI variable the probe will report. `db` with the Microsoft
/// UEFI CAs and the release leaf is a few kilobytes; the bound exists so a
/// firmware with an implausible variable cannot overrun the output buffer,
/// and it is reported as `unreadable` rather than truncated.
const efivar_max_bytes = 32 * 1024;

var variable_buffer: [efivar_max_bytes]u8 = undefined;

const VariableRead = union(enum) {
    ok: []const u8,
    missing,
    unreadable,
    /// The variable is larger than the probe is willing to report.
    too_large,
};

/// Reads one efivarfs variable whole, distinguishing "no such variable" from
/// "could not read it" so the harness can tell a firmware that never enrolled
/// `db` from one that will not hand it over.
fn readVariable(path: []const u8, out: []u8) VariableRead {
    var buffer: [path_max]u8 = undefined;
    const c_path = terminate(&buffer, path) orelse return .unreadable;
    const open_rc = linux.open(c_path, .{ .ACCMODE = .RDONLY }, 0);
    switch (linux.errno(open_rc)) {
        .SUCCESS => {},
        .NOENT => return .missing,
        else => return .unreadable,
    }
    const fd: i32 = @intCast(open_rc);
    defer _ = linux.close(fd);
    var filled: usize = 0;
    while (filled < out.len) {
        const rc = linux.read(fd, out[filled..].ptr, out.len - filled);
        if (linux.errno(rc) != .SUCCESS) return .unreadable;
        if (rc == 0) return .{ .ok = out[0..filled] };
        filled += rc;
    }
    // A full buffer may mean there is more; refuse rather than report a
    // truncated signature database as if it were the whole thing.
    var overflow: [1]u8 = undefined;
    const rc = linux.read(fd, &overflow, overflow.len);
    if (linux.errno(rc) != .SUCCESS) return .unreadable;
    if (rc != 0) return .too_large;
    return .{ .ok = out[0..filled] };
}

fn emitEfivarFailure(
    name: []const u8,
    status: contract.EfivarStatus,
    mounted: Mounted,
) void {
    emit("{s} name={s} status={s} mount={s}", .{
        contract.efivar_prefix,
        name,
        status.key(),
        mounted.mount.key(),
    });
    if (mounted.dir.len != 0) emit(" mount_point={s}", .{mounted.dir});
    if (mounted.found.len != 0) emit(" filesystem={s}", .{mounted.found});
    emit("\n", .{});
}

/// Emits one variable's `efivar` line from its raw efivarfs bytes.
///
/// Split out from the reading so the producer's exact wire format is testable
/// on the host against `contract.parseEfivarLine`, which is the consumer.
fn emitEfivarValue(name: []const u8, mounted: Mounted, bytes: []const u8) bool {
    // Every efivarfs variable is four little-endian attribute bytes followed
    // by its data; anything shorter is not one.
    if (bytes.len < 4) {
        emitEfivarFailure(name, .malformed, mounted);
        return false;
    }
    const attributes = std.mem.readInt(u32, bytes[0..4], .little);
    const data = bytes[4..];
    emit(
        "{s} name={s} status=ok mount={s} mount_point={s} filesystem={s} " ++
            "attributes=0x{x:0>8} bytes={d} data=",
        .{
            contract.efivar_prefix,
            name,
            mounted.mount.key(),
            mounted.dir,
            contract.efivars_filesystem,
            attributes,
            data.len,
        },
    );
    for (data) |byte| emit("{x:0>2}", .{byte});
    emit("\n", .{});
    return true;
}

/// Prints one `efivar` line per requested variable, mounting efivarfs first if
/// nothing else already has and unmounting again afterwards.
///
/// Every variable is reported even when an earlier one failed, so one absent
/// variable never hides the state of the rest.
fn reportEfivars(names: []const [*:0]const u8) bool {
    const mounted = acquire(
        contract.efivars_mount_point,
        contract.efivars_private_mount_point,
        contract.efivars_filesystem,
    );
    defer release(mounted);

    if (mounted.status) |status| {
        for (names) |raw| emitEfivarFailure(std.mem.span(raw), status, mounted);
        return false;
    }

    var complete = true;
    for (names) |raw| {
        const name = std.mem.span(raw);
        var path_buffer: [path_max]u8 = undefined;
        const path = std.fmt.bufPrint(
            &path_buffer,
            "{s}/{s}",
            .{ mounted.dir, name },
        ) catch {
            emitEfivarFailure(name, .unreadable, mounted);
            complete = false;
            continue;
        };
        const read = readVariable(path, &variable_buffer);
        const bytes = switch (read) {
            .ok => |value| value,
            .missing => {
                emitEfivarFailure(name, .missing, mounted);
                complete = false;
                continue;
            },
            .unreadable, .too_large => {
                emitEfivarFailure(name, .unreadable, mounted);
                complete = false;
                continue;
            },
        };
        if (!emitEfivarValue(name, mounted, bytes)) complete = false;
    }
    return complete;
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

const usage =
    "usage: ubuntu2604-runtime-contract-probe " ++
    "(contract | requirement <id>... | efivar <name>... | filesystem <path>...)\n";

pub fn main(init: std.process.Init.Minimal) u8 {
    const args = init.args.vector;
    if (args.len < 2) {
        emit(usage, .{});
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
        return if (output_truncated) 1 else 0;
    }
    if (std.mem.eql(u8, command, "requirement")) {
        if (args.len < 3) {
            emit("usage: ubuntu2604-runtime-contract-probe requirement <id>...\n", .{});
            flush();
            return 2;
        }
        const complete = reportRequirements(args[2..]);
        flush();
        return if (complete and !output_truncated) 0 else 1;
    }
    if (std.mem.eql(u8, command, "efivar")) {
        if (args.len < 3) {
            emit("usage: ubuntu2604-runtime-contract-probe efivar <name>...\n", .{});
            flush();
            return 2;
        }
        const complete = reportEfivars(args[2..]);
        flush();
        return if (complete and !output_truncated) 0 else 1;
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
        return if (complete and !output_truncated) 0 else 1;
    }
    emit(usage, .{});
    flush();
    return 2;
}

// ---------------------------------------------------------------------------
// Host-side unit tests.
//
// The probe runs in a guest, but the parts of it that decide what a report
// says are pure: `/proc/mounts` interpretation, the mount point a lockdown
// file is exposed through, and the exact bytes of an `efivar` line. Testing
// them here means the wire format the acceptance harness parses is checked
// against the code that produces it, not against a copy of it.
// ---------------------------------------------------------------------------

fn resetOutput() void {
    output_len = 0;
    output_truncated = false;
}

fn reported() []const u8 {
    return output_buffer[0..output_len];
}

test "the live filesystem at a mount point is the last one mounted there" {
    const table =
        "proc /proc proc rw,relatime 0 0\n" ++
        "efivarfs /sys/firmware/efi/efivars efivarfs rw,relatime 0 0\n" ++
        "tmpfs /run tmpfs rw,relatime 0 0\n";
    try std.testing.expectEqualStrings(
        "efivarfs",
        mountedFilesystemIn(table, "/sys/firmware/efi/efivars").?,
    );
    try std.testing.expect(mountedFilesystemIn(table, "/sys/kernel/security") == null);

    // A later line shadows an earlier one at the same point, and the shadowing
    // filesystem is the one a read would actually reach.
    const shadowed = table ++ "tmpfs /sys/firmware/efi/efivars tmpfs rw 0 0\n";
    try std.testing.expectEqualStrings(
        "tmpfs",
        mountedFilesystemIn(shadowed, "/sys/firmware/efi/efivars").?,
    );

    // A truncated table must not be mistaken for a mount.
    try std.testing.expect(mountedFilesystemIn("efivarfs", "efivarfs") == null);
    try std.testing.expect(mountedFilesystemIn("", "/") == null);
}

test "a lockdown path resolves to the mount point that exposes it" {
    try std.testing.expectEqualStrings(
        "/sys/kernel/security",
        parentOf("/sys/kernel/security/lockdown"),
    );
    try std.testing.expectEqualStrings("/", parentOf("/lockdown"));
    try std.testing.expectEqualStrings("lockdown", parentOf("lockdown"));
}

test "an emitted efivar line is exactly what the harness parses" {
    resetOutput();
    const mounted: Mounted = .{
        .dir = contract.efivars_private_mount_point,
        .mount = .probe,
    };
    // Four little-endian attribute bytes, then the data.
    const raw = [_]u8{ 0x27, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expect(emitEfivarValue(contract.signature_database_variable, mounted, &raw));

    const line = std.mem.trimEnd(u8, reported(), "\n");
    const parsed = try contract.parseEfivarLine(line);
    try std.testing.expectEqualStrings(contract.signature_database_variable, parsed.name);
    try std.testing.expectEqual(contract.EfivarStatus.ok, parsed.status);
    try std.testing.expectEqual(contract.EfivarMount.probe, parsed.mount);
    try std.testing.expectEqualStrings(
        contract.efivars_private_mount_point,
        parsed.mount_point,
    );
    try std.testing.expectEqualStrings(contract.efivars_filesystem, parsed.filesystem);
    try std.testing.expectEqual(contract.signature_database_attributes, parsed.attributes);
    var decoded: [4]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
        try parsed.decode(&decoded),
    );
}

test "a variable with no room for attribute bytes is reported malformed" {
    const mounted: Mounted = .{
        .dir = contract.efivars_mount_point,
        .mount = .existing,
    };
    for ([_]usize{ 0, 1, 2, 3 }) |length| {
        resetOutput();
        const raw = [_]u8{0} ** 4;
        try std.testing.expect(
            !emitEfivarValue(contract.secure_boot_variable, mounted, raw[0..length]),
        );
        const parsed = try contract.parseEfivarLine(std.mem.trimEnd(u8, reported(), "\n"));
        try std.testing.expectEqual(contract.EfivarStatus.malformed, parsed.status);
        try std.testing.expectEqual(@as(usize, 0), parsed.data_hex.len);
    }

    // Exactly four bytes is a well-formed variable with no data, not a
    // malformed one: `db` can legitimately be empty on unenrolled firmware.
    resetOutput();
    const empty = [_]u8{ 0x27, 0x00, 0x00, 0x00 };
    try std.testing.expect(
        emitEfivarValue(contract.signature_database_variable, mounted, &empty),
    );
    const parsed = try contract.parseEfivarLine(std.mem.trimEnd(u8, reported(), "\n"));
    try std.testing.expectEqual(contract.EfivarStatus.ok, parsed.status);
    try std.testing.expectEqual(@as(usize, 0), parsed.data_hex.len);
}

test "every way of failing to reach a variable parses as that failure" {
    const cases = [_]struct { status: contract.EfivarStatus, mounted: Mounted }{
        .{ .status = .not_mounted, .mounted = Mounted.failed(.not_mounted, "") },
        .{ .status = .permission_denied, .mounted = Mounted.failed(.permission_denied, "") },
        .{ .status = .wrong_filesystem, .mounted = Mounted.failed(.wrong_filesystem, "sysfs") },
        .{
            .status = .missing,
            .mounted = .{ .dir = contract.efivars_mount_point, .mount = .existing },
        },
        .{
            .status = .unreadable,
            .mounted = .{ .dir = contract.efivars_private_mount_point, .mount = .probe },
        },
    };
    for (cases) |case| {
        resetOutput();
        emitEfivarFailure(contract.signature_database_variable, case.status, case.mounted);
        const parsed = try contract.parseEfivarLine(std.mem.trimEnd(u8, reported(), "\n"));
        try std.testing.expectEqual(case.status, parsed.status);
        try std.testing.expectEqual(case.mounted.mount, parsed.mount);
        try std.testing.expectEqualStrings(case.mounted.found, parsed.filesystem);
        try std.testing.expectEqual(@as(u32, 0), parsed.attributes);
    }
}

test "a variable too large for the report is refused rather than truncated" {
    resetOutput();
    const mounted: Mounted = .{
        .dir = contract.efivars_mount_point,
        .mount = .existing,
    };
    // Two variables of the maximum size cannot both fit, and the second must
    // set the truncation flag rather than emit a half-written database.
    const raw = [_]u8{0} ** efivar_max_bytes;
    _ = emitEfivarValue(contract.signature_database_variable, mounted, &raw);
    try std.testing.expect(!output_truncated);
    _ = emitEfivarValue(contract.secure_boot_variable, mounted, &raw);
    try std.testing.expect(output_truncated);
    resetOutput();
}

test "a probe-established mount is released and an inherited one is not" {
    // `release` must be a no-op for anything the probe did not mount, or a
    // successful check would tear down the guest's own efivarfs.
    release(.{ .dir = contract.efivars_mount_point, .mount = .existing });
    release(.{ .dir = "", .mount = .none });
    // The two mount points must differ, or "unmount only what we mounted"
    // would not be expressible.
    try std.testing.expect(!std.mem.eql(
        u8,
        contract.efivars_mount_point,
        contract.efivars_private_mount_point,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        "/sys/kernel/security",
        securityfs_private_mount_point,
    ));
}
