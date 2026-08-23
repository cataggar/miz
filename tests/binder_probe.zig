//! Static, architecture-matched probe used only by Azure core acceptance
//! (`scripts/ubuntu2604_azure_acceptance.sh`) to prove the guest's Binder
//! IPC devices are not merely present as files but actually respond to the
//! kernel driver's own ioctl protocol. It is built ad hoc for the
//! candidate's guest architecture -- matching the `efi_signing_probe.zig`
//! pattern -- transferred over the already-established SSH channel, and run
//! as a throwaway binary; it is never part of any published image.
//!
//! Two subcommands, both read-only from an acceptance standpoint:
//!
//!   - `version <device>`: issues the `BINDER_VERSION` ioctl and prints the
//!     driver's reported protocol version, proving the node is a live
//!     Binder device rather than a stale or unrelated character device.
//!   - `alloc <control> <name>`: issues `BINDER_CTL_ADD` against a binderfs
//!     `binder-control` node, proving it can dynamically allocate a new
//!     binder device -- the property that distinguishes binderfs from a
//!     fixed legacy device count.
//!
//! The ioctl request codes and structure layouts below come from the
//! upstream kernel's public, stable uAPI headers
//! (`include/uapi/linux/android/binder.h` and `.../binderfs.h`); they do not
//! depend on any specific downstream distribution or container project.
const std = @import("std");
const linux = std.os.linux;

/// `struct binder_version` (`<linux/android/binder.h>`): the driver fills
/// this in when asked with `BINDER_VERSION`.
const BinderVersion = extern struct {
    protocol_version: i32 = 0,
};

/// `BINDER_VERSION = _IOWR('b', 9, struct binder_version)`.
const BINDER_VERSION: u32 = 0xc0046209;

/// The Binder wire protocol version reported by every in-tree driver build
/// since 64-bit binder IPC became the default; used as a sanity floor so a
/// successful ioctl against an unrelated device can't silently pass.
const BINDER_MIN_PLAUSIBLE_PROTOCOL_VERSION: i32 = 7;

/// `BINDERFS_MAX_NAME` (`<linux/android/binderfs.h>`): the longest name a
/// dynamically allocated binder device may have, not counting the
/// terminating zero byte.
const BINDERFS_MAX_NAME = 255;

/// `struct binderfs_device` (`<linux/android/binderfs.h>`): the caller fills
/// in `name`; the driver fills in `major`/`minor` on success.
const BinderfsDevice = extern struct {
    name: [BINDERFS_MAX_NAME + 1]u8 = [_]u8{0} ** (BINDERFS_MAX_NAME + 1),
    major: u32 = 0,
    minor: u32 = 0,
};

/// `BINDER_CTL_ADD = _IOWR('b', 1, struct binderfs_device)`.
const BINDER_CTL_ADD: u32 = 0xc1086201;

fn openReadWrite(path: [:0]const u8) !i32 {
    const rc = linux.open(path.ptr, .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
    return @intCast(rc);
}

fn versionCommand(device_path: [:0]const u8) u8 {
    const fd = openReadWrite(device_path) catch {
        std.debug.print("binder_probe: open {s} failed\n", .{device_path});
        return 1;
    };
    defer _ = linux.close(fd);

    var version = BinderVersion{};
    const rc = linux.ioctl(fd, BINDER_VERSION, @intFromPtr(&version));
    if (linux.errno(rc) != .SUCCESS) {
        std.debug.print("binder_probe: BINDER_VERSION ioctl on {s} failed\n", .{device_path});
        return 1;
    }
    if (version.protocol_version < BINDER_MIN_PLAUSIBLE_PROTOCOL_VERSION) {
        std.debug.print(
            "binder_probe: {s} reported an implausible protocol version {d}\n",
            .{ device_path, version.protocol_version },
        );
        return 1;
    }
    std.debug.print("version {s} protocol_version={d}\n", .{ device_path, version.protocol_version });
    return 0;
}

fn allocCommand(control_path: [:0]const u8, name: []const u8) u8 {
    if (name.len == 0 or name.len > BINDERFS_MAX_NAME) {
        std.debug.print("binder_probe: device name length is out of range\n", .{});
        return 1;
    }
    const fd = openReadWrite(control_path) catch {
        std.debug.print("binder_probe: open {s} failed\n", .{control_path});
        return 1;
    };
    defer _ = linux.close(fd);

    var device = BinderfsDevice{};
    @memcpy(device.name[0..name.len], name);
    const rc = linux.ioctl(fd, BINDER_CTL_ADD, @intFromPtr(&device));
    if (linux.errno(rc) != .SUCCESS) {
        std.debug.print("binder_probe: BINDER_CTL_ADD ioctl on {s} failed\n", .{control_path});
        return 1;
    }
    std.debug.print("alloc {s} major={d} minor={d}\n", .{ name, device.major, device.minor });
    return 0;
}

fn printUsage() void {
    std.debug.print(
        "usage: binder_probe version <device> | binder_probe alloc <control> <name>\n",
        .{},
    );
}

pub fn main(init: std.process.Init.Minimal) noreturn {
    const argv = init.args.vector;
    if (argv.len == 3 and std.mem.eql(u8, std.mem.span(argv[1]), "version")) {
        std.process.exit(versionCommand(std.mem.span(argv[2])));
    }
    if (argv.len == 4 and std.mem.eql(u8, std.mem.span(argv[1]), "alloc")) {
        std.process.exit(allocCommand(std.mem.span(argv[2]), std.mem.span(argv[3])));
    }
    printUsage();
    std.process.exit(2);
}
