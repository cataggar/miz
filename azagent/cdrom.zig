//! Locates, mounts, and reads `ovf-env.xml` off a provisioning CD-ROM/DVD.
//! Azure media is the default. Synthetic local media must also contain the
//! explicit `vmiz-local-provisioning` marker used by vmizinit to select
//! `azagent --skip-ready`; an OVF document alone never selects local mode.
//!
//! Deliberately narrower than upstream's `get_dvd_device` (which regex-
//! matches a long list of device names across many hypervisors/distros):
//! Azure's Hyper-V media and the controlled QEMU acceptance topology both
//! expose `/dev/sr0` (with `/dev/cdrom` retained as a conventional alias).
//!
//! Uses direct `mount(2)`/`umount(2)` syscalls (matching `vmizinit`'s
//! style) rather than shelling out to `mount`/`umount`. Not covered by an
//! automated test: it requires a real block device, which isn't available
//! in a unit-test sandbox -- exercised only via manual/real-VM
//! verification (and, indirectly, by `ovf.zig`'s parser tests, which cover
//! everything downstream of actually getting the bytes off the media).
const std = @import("std");
const linux = std.os.linux;

const device_candidates = [_][*:0]const u8{ "/dev/sr0", "/dev/cdrom" };
const mount_point = "/run/azagent/provision-media";
const fstypes = [_][*:0]const u8{ "udf", "iso9660" };

pub const ProbeResult = enum {
    absent,
    azure,
    local,
    indeterminate,
};

pub const local_provisioning_marker = "vmiz-local-provisioning";

pub const ReadError = error{
    NoProvisioningMediaFound,
    MountFailed,
} || std.mem.Allocator.Error || std.Io.Dir.CreateDirPathError || std.Io.Dir.OpenError || std.Io.Dir.ReadFileAllocError;

/// Checks for readable provisioning media without consuming the document.
/// All paths must be dedicated to the caller so a failed probe cannot
/// interfere with `readOvfEnv`.
pub fn probe(
    probe_mount_point: [*:0]const u8,
    ovf_env_path: [*:0]const u8,
    local_marker_path: [*:0]const u8,
) ProbeResult {
    var mounted = false;
    var device_found = false;
    for (device_candidates) |device| {
        if (!deviceExists(device)) continue;
        device_found = true;
        for (fstypes) |fstype| {
            const rc = linux.mount(device, probe_mount_point, fstype, linux.MS.RDONLY, 0);
            if (linux.errno(rc) == .SUCCESS) {
                mounted = true;
                break;
            }
        }
        if (mounted) break;
    }
    if (!mounted) return if (device_found) .indeterminate else .absent;

    const fd_rc = linux.open(ovf_env_path, .{ .ACCMODE = .RDONLY }, 0);
    const readable = linux.errno(fd_rc) == .SUCCESS;
    if (readable) _ = linux.close(@intCast(fd_rc));
    const marker_fd_rc = linux.open(local_marker_path, .{ .ACCMODE = .RDONLY }, 0);
    const local_marker_readable = linux.errno(marker_fd_rc) == .SUCCESS;
    if (local_marker_readable) _ = linux.close(@intCast(marker_fd_rc));

    _ = unmount(probe_mount_point);
    return classifyMountedMedia(readable, local_marker_readable);
}

fn classifyMountedMedia(ovf_readable: bool, local_marker_readable: bool) ProbeResult {
    if (!ovf_readable) return .indeterminate;
    return if (local_marker_readable) .local else .azure;
}

/// Mounts the first working `(device, fstype)` combination from
/// `device_candidates`/`fstypes` at `mount_point`, reads `ovf-env.xml` from
/// it, then unmounts. Returns the caller-owned file content.
pub fn readOvfEnv(allocator: std.mem.Allocator, io: std.Io) ReadError![]u8 {
    try std.Io.Dir.cwd().createDirPath(io, mount_point);

    var mounted = false;
    var device_found = false;
    for (device_candidates) |device| {
        if (!deviceExists(device)) continue;
        device_found = true;
        for (fstypes) |fstype| {
            const rc = linux.mount(device, mount_point, fstype, linux.MS.RDONLY, 0);
            if (linux.errno(rc) == .SUCCESS) {
                mounted = true;
                break;
            }
        }
        if (mounted) break;
    }
    if (!mounted) return if (device_found) error.MountFailed else error.NoProvisioningMediaFound;
    defer _ = unmount(mount_point);

    var dir = try std.Io.Dir.cwd().openDir(io, mount_point, .{});
    defer dir.close(io);
    return dir.readFileAlloc(io, "ovf-env.xml", allocator, .limited(1024 * 1024));
}

fn deviceExists(path: [*:0]const u8) bool {
    const rc = linux.access(path, linux.F_OK);
    return linux.errno(rc) == .SUCCESS;
}

fn unmount(path: [*:0]const u8) bool {
    while (true) {
        const rc = linux.umount(path);
        const e = linux.errno(rc);
        if (e == .SUCCESS) return true;
        if (e != .INTR) break;
    }

    return linux.errno(linux.umount2(path, linux.MNT.DETACH)) == .SUCCESS;
}

test "mounted media classification requires an explicit local marker" {
    try std.testing.expectEqual(ProbeResult.azure, classifyMountedMedia(true, false));
    try std.testing.expectEqual(ProbeResult.local, classifyMountedMedia(true, true));
    try std.testing.expectEqual(ProbeResult.indeterminate, classifyMountedMedia(false, false));
    try std.testing.expectEqual(ProbeResult.indeterminate, classifyMountedMedia(false, true));
}
