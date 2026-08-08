//! What both executors need to know about regenerating an initramfs, in one
//! place so the host, the privileged worker and the guest agent cannot drift.
//!
//! Nothing here reads a filesystem. It is the shape of the operation -- what a
//! kernel release may be called, and in later work where the tool lives and
//! what the command line is -- so that the host can refuse a request the
//! target cannot satisfy, and the two backends can carry out the same
//! operation rather than two similar ones.
//!
//! The same charter as `selinux.zig` and `packages.zig`, and for the same
//! reason: this module reaches the guest agent through `vm_control`, and the
//! guest agent is a static, libc-free PID 1 that imports `std` and nothing
//! else.
//!
//! Not to be confused with `verity_tooling.zig`, which inspects the *contents*
//! of an initramfs image for dm-verity userspace tooling.

const std = @import("std");

/// The longest kernel release either backend will act on.
///
/// A release is not free-form text that happens to be echoed back: it becomes
/// a `dracut --kver` argument and the `<release>` in
/// `/boot/initramfs-<release>.img`, so it wants a bound. 128 bytes is far
/// above anything `uname -r` produces -- Azure Linux's longest is under 30 --
/// and far below any limit a path or an argv would hit, which is what a bound
/// on adversarial input is for.
pub const max_kernel_release = 128;

/// Whether a string is a kernel release both backends will act on.
///
/// The character rule is the intersection of what `uname -r` produces and what
/// is safe as a path component: alphanumerics plus `.`, `_`, `+`, `-` and `~`,
/// starting with an alphanumeric. No `/` and no leading `.`, so a release can
/// name neither a directory to traverse into nor `..`.
///
/// This used to exist three times -- here in spirit, as
/// `unsafe_chroot.validKernelRelease` and as
/// `customize.validUnsafeKernelRelease` -- and the copies disagreed: only the
/// control-document one bounded the length, while the comment on it claimed to
/// mirror a `customize` function that had no bound at all.
///
/// It is also what an rpm `%{ARCH}` is held to. That is not a pun: an
/// architecture is a path component and an argv element under exactly the same
/// conditions, and giving it a second rule that happened to be identical is
/// how the third copy would start.
pub fn validKernelRelease(kernel: []const u8) bool {
    if (kernel.len == 0 or kernel.len > max_kernel_release) return false;
    if (!std.ascii.isAlphanumeric(kernel[0])) return false;
    for (kernel[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~')
        {
            return false;
        }
    }
    return true;
}

test "validKernelRelease accepts what uname -r produces and refuses a path" {
    const cases = [_]struct {
        kernel: []const u8,
        valid: bool,
        why: []const u8,
    }{
        .{
            .kernel = "6.12.0-1.azl3",
            .valid = true,
            .why = "the ordinary Azure Linux shape",
        },
        .{
            .kernel = "6.12.0-1.azl4.aarch64",
            .valid = true,
            .why = "an arch suffix is just more of the same characters",
        },
        .{
            .kernel = "6.6.0-rc1+",
            .valid = true,
            .why = "a locally built kernel carries the `+` uname appends",
        },
        .{
            .kernel = "x86_64",
            .valid = true,
            .why = "the same rule is what an rpm %{ARCH} is held to",
        },
        .{
            .kernel = "",
            .valid = false,
            .why = "an empty release would make /boot/initramfs-.img",
        },
        .{
            .kernel = "../../etc/passwd",
            .valid = false,
            .why = "the traversal the leading-alphanumeric rule exists for",
        },
        .{
            .kernel = "6.12.0/1",
            .valid = false,
            .why = "a separator would make the release name a directory",
        },
        .{
            .kernel = ".6.12.0",
            .valid = false,
            .why = "a leading dot is how `..` starts",
        },
        .{
            .kernel = "6.12.0 -1",
            .valid = false,
            .why = "a space would split one argv element into two",
        },
        .{
            .kernel = "-6.12.0",
            .valid = false,
            .why = "a leading `-` is a dracut option, not a release",
        },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.valid, validKernelRelease(case.kernel));
    }
}

test "validKernelRelease bounds the length, at the boundary" {
    var buffer: [max_kernel_release + 1]u8 = undefined;
    @memset(&buffer, 'a');

    // The bound the control document has always carried, and which the two
    // host-side copies did not, so that a release cannot be a kilobyte of
    // otherwise-valid characters on a command line.
    try std.testing.expect(validKernelRelease(buffer[0..max_kernel_release]));
    try std.testing.expect(!validKernelRelease(buffer[0 .. max_kernel_release + 1]));
    try std.testing.expect(validKernelRelease(buffer[0..1]));
}
