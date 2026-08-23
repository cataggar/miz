//! Tiny static Binder workload device-usability probe.
//!
//! Not part of any published image. `build.zig` cross-builds this per guest
//! architecture only when the Ubuntu 26.04 core flavor is selected, and
//! `tests/ubuntu2604_acceptance.zig` pushes the resulting static binary into
//! the running guest over SSH so device usability can be confirmed by
//! actually opening each device and issuing `BINDER_VERSION`, rather than
//! only checking that the device path exists.
//!
//! Usage: ubuntu2604-binder-probe <device-path>...
//!
//! Prints exactly one line per argument, in the form
//! `device=<path> status=(ok|open-failed|ioctl-failed)[ ...]`, and always
//! exits 0 when at least one device path was given -- callers determine
//! pass/fail by parsing the per-device `status=` field, not the exit code,
//! so a single failing device does not hide the diagnostics for the rest.
//! Exits 2 (and prints nothing else) only when invoked with no arguments at
//! all, which is a harness usage error rather than guest state.
const std = @import("std");
const linux = std.os.linux;

/// `_IOWR('b', 9, struct binder_version)` from the upstream kernel UAPI
/// header `linux/android/binder.h`. Derived rather than hardcoded so the
/// encoding is auditable: x86_64 and aarch64 -- this probe's only two guest
/// targets -- both use the asm-generic ioctl number layout, unlike a handful
/// of other architectures, so one constant is valid for both.
const binder_version_request: u32 = iowr(3, 'b', 9, @sizeOf(BinderVersion));

const BinderVersion = extern struct {
    protocol_version: i32 = 0,
};

fn iowr(direction: u32, kind: u8, nr: u8, size: usize) u32 {
    return (direction << 30) | (@as(u32, @intCast(size)) << 16) | (@as(u32, kind) << 8) | nr;
}

fn printLine(comptime fmt: []const u8, args: anytype) void {
    var buf: [320]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = linux.write(1, msg.ptr, msg.len);
}

fn probeDevice(path: [*:0]const u8) void {
    const open_rc = linux.open(path, .{ .ACCMODE = .RDWR }, 0);
    const open_err = linux.errno(open_rc);
    if (open_err != .SUCCESS) {
        printLine("device={s} status=open-failed errno={d}\n", .{ std.mem.span(path), @intFromEnum(open_err) });
        return;
    }
    const fd: i32 = @intCast(open_rc);
    defer _ = linux.close(fd);

    var version = BinderVersion{};
    const ioctl_rc = linux.ioctl(fd, binder_version_request, @intFromPtr(&version));
    const ioctl_err = linux.errno(ioctl_rc);
    if (ioctl_err != .SUCCESS) {
        printLine("device={s} status=ioctl-failed errno={d}\n", .{ std.mem.span(path), @intFromEnum(ioctl_err) });
        return;
    }
    printLine("device={s} status=ok protocol_version={d}\n", .{ std.mem.span(path), version.protocol_version });
}

pub fn main(init: std.process.Init.Minimal) u8 {
    const args = init.args.vector;
    if (args.len < 2) {
        printLine("usage: ubuntu2604-binder-probe <device-path>...\n", .{});
        return 2;
    }
    for (args[1..]) |arg| probeDevice(arg);
    return 0;
}
