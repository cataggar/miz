//! Host capability probe for the isolated `vm` customization backend.
//!
//! This module deliberately performs no discovery: the emulator is named
//! explicitly by `customize.VmPolicy`, so a run can never silently fall back
//! to a host-architecture emulator or to software emulation. Every check runs
//! before `preserved_image.transactRaw` copies anything, so a rejection leaves
//! the source and the output untouched.

const std = @import("std");
const builtin = @import("builtin");
const customize = @import("customize.zig");

const Io = std.Io;

/// Extra free space required beyond the raw stage and the published output, to
/// cover the control and result disks and filesystem overhead.
pub const workspace_overhead_bytes: u64 = 512 * 1024 * 1024;

/// Reports whether this host can run the plan's VM backend.
///
/// `.missing` means the host lacks a resource the plan requires and the
/// operator can install or free it. `.unsupported` means the plan itself is
/// not executable here.
pub fn available(io: Io, plan: *const customize.ResolvedPlan) customize.CapabilityState {
    const data = plan.data;
    const policy = data.execution.vm orelse return .unsupported;
    if (data.execution.backend != .vm) return .unsupported;

    if (!emulatorExecutable(io, policy.emulator_command)) return .missing;

    switch (policy.acceleration) {
        .hardware => {
            if (data.architectures.runner != data.architectures.host) return .unsupported;
            if (!hardwareAccelerationAvailable(io)) return .missing;
        },
        .software => {},
    }

    if (data.input != .disk) return .unsupported;
    if (!workspaceHasFreeSpace(io, data.execution.workspace_path, data.input.disk.path)) {
        return .missing;
    }
    return .available;
}

fn emulatorExecutable(io: Io, command: []const u8) bool {
    // Resolution of a bare name against `PATH` belongs to the caller that
    // builds the policy, so provenance records the exact binary that ran.
    if (!std.fs.path.isAbsolute(command)) return false;
    return pathExecutable(io, command);
}

fn pathExecutable(io: Io, path: []const u8) bool {
    const cwd = Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{}) catch return false;
    if (stat.kind != .file) return false;
    cwd.access(io, path, .{ .execute = true }) catch return false;
    return true;
}

fn hardwareAccelerationAvailable(io: Io) bool {
    return switch (builtin.os.tag) {
        .linux => blk: {
            Io.Dir.cwd().access(io, "/dev/kvm", .{ .read = true, .write = true }) catch
                break :blk false;
            break :blk true;
        },
        // Hardware acceleration on these platforms is provided by the
        // hypervisor framework rather than a device node, and cannot be
        // probed without launching the emulator.
        .macos, .windows => true,
        else => false,
    };
}

fn workspaceHasFreeSpace(io: Io, workspace_path: []const u8, source_path: []const u8) bool {
    const cwd = Io.Dir.cwd();
    const source = cwd.statFile(io, source_path, .{}) catch return false;
    const doubled = std.math.mul(u64, source.size, 2) catch return false;
    const required = std.math.add(u64, doubled, workspace_overhead_bytes) catch return false;

    // The workspace itself is created by execution, so when it is absent the
    // parent directory is what must have room.
    const probe_path = if (pathExists(io, workspace_path))
        workspace_path
    else
        std.fs.path.dirname(workspace_path) orelse ".";
    const free_bytes = freeBytes(probe_path) orelse return true;
    return free_bytes >= required;
}

fn pathExists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// The 64-bit Linux `struct statfs`. Zig's standard library does not expose
/// `statfs`, and there is no portable free-space API in `std.Io`.
const LinuxStatfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};

/// Bytes available to an unprivileged writer, or null when the host offers no
/// way to ask. A null result must not fail the preflight: an unknown amount of
/// free space is not the same as too little.
fn freeBytes(path: []const u8) ?u64 {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return null;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= path_buffer.len) return null;
    @memcpy(path_buffer[0..path.len], path);
    path_buffer[path.len] = 0;

    var info: LinuxStatfs = undefined;
    const result = std.os.linux.syscall2(
        .statfs,
        @intFromPtr(&path_buffer),
        @intFromPtr(&info),
    );
    if (std.os.linux.errno(result) != .SUCCESS) return null;
    if (info.bsize <= 0) return null;
    return std.math.mul(u64, info.bavail, @intCast(info.bsize)) catch null;
}

test "an emulator command must be an absolute path to an executable file" {
    const io = std.testing.io;
    try std.testing.expect(!emulatorExecutable(io, ""));
    try std.testing.expect(!emulatorExecutable(io, "qemu-system-x86_64"));
    try std.testing.expect(!emulatorExecutable(io, "/nonexistent/qemu-system-x86_64"));
    // A directory is not an emulator even though the path resolves.
    try std.testing.expect(!emulatorExecutable(io, "/tmp"));
}

test "free space is reported for an existing directory on Linux" {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return error.SkipZigTest;
    const free = freeBytes(".") orelse return error.SkipZigTest;
    try std.testing.expect(free > 0);
    try std.testing.expect(freeBytes("/nonexistent-zvmi-vm-backend-probe") == null);
}
