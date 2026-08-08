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

/// The one generator either backend knows how to drive.
///
/// Named rather than spelled at each refusal so that the check the host makes
/// at capability time and the two the privileged worker makes on its own side
/// of the boundary cannot come to disagree about what the word is.
pub const generator = "dracut";

/// Where the generator is looked for inside the target root. An absolute path
/// rather than a name on `PATH`, because the command runs in a chroot the
/// caller does not control the environment of.
pub const tool_path = "/usr/bin/" ++ generator;

/// The copy is a separate tool because the image is built aside and moved into
/// place, and `cp --remove-destination` is the one form that replaces a file
/// the target may have made immutable or hard-linked.
pub const copy_tool_path = "/usr/bin/cp";

/// Where the generator is told to put its scratch files and its output.
///
/// `/run` in both backends: a tmpfs the target already has, private to the
/// run, and not a directory the published image keeps.
pub const scratch_directory = "/run";

/// Where the image is built before it is moved into place.
///
/// Built aside and copied rather than written straight to `/boot`, so a
/// generator that fails partway through cannot leave the image with a
/// truncated initramfs at the path the bootloader names.
pub const temporary_image_path = scratch_directory ++ "/zvmi-initramfs.img";

/// Where the kernels a target has installed are enumerated from.
pub const modules_directory = "/lib/modules";

/// The files `depmod` writes as a kernel package installs.
///
/// dracut's own `--regenerate-all` iterates `/lib/modules/*` and skips any
/// entry carrying neither, which is what separates an installed kernel from a
/// directory that merely sits beside one -- a firmware drop, or what a removed
/// package left behind. Both backends copy the rule rather than inventing one,
/// so neither can disagree with the tool it hands the answer to.
pub const module_dependency_markers = [_][]const u8{ "modules.dep", "modules.dep.bin" };

/// The published image for a kernel release, inside the target root.
///
/// The guest-visible path and only that: the privileged worker prefixes it
/// with the mounted root itself, because a shared module that knew about
/// `<root>` would be a shared module that had opinions about the host's
/// filesystem.
pub fn imagePath(allocator: std.mem.Allocator, kernel_release: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/boot/initramfs-{s}.img", .{kernel_release});
}

/// The command that regenerates one initramfs.
///
/// Returned by value rather than allocated: every element but the release is a
/// constant, and a fixed-length array is one fewer thing for a caller running
/// as root to get wrong.
///
/// `--force` because the target already has an image at the final path and the
/// point of the run is to replace it. `--no-hostonly` because the image is
/// built for whatever machine boots it rather than for the one building it,
/// which is the whole difference between an image and a machine's own
/// initramfs.
pub fn regenerateArgv(kernel_release: []const u8) [8][]const u8 {
    return .{
        tool_path,
        "--force",
        "--no-hostonly",
        "--tmpdir",
        scratch_directory,
        "--kver",
        kernel_release,
        temporary_image_path,
    };
}

/// The command that moves the finished image to where the bootloader names it.
///
/// `--remove-destination` rather than a plain overwrite: the destination may
/// be a hard link into a package's own file, and writing through it would
/// change a file the package manager believes it owns.
pub fn installArgv(image_path: []const u8) [4][]const u8 {
    return .{
        copy_tool_path,
        "--remove-destination",
        temporary_image_path,
        image_path,
    };
}

/// Why a `/lib/modules` entry was not treated as an installed kernel.
///
/// One enum, aliased by `customize.SkippedKernelReason` and
/// `vm_control.SkippedKernelReason`, so that a reason added on one side cannot
/// go unmapped on the other.
pub const SkipReason = enum {
    /// Not a usable release string. The same rule a declared release is held
    /// to: a name that could not be requested cannot become acceptable by
    /// being discovered instead.
    invalid_release_name,
    /// Not a directory, or gone between the read and the open.
    not_a_module_directory,
    /// No `modules.dep` or `modules.dep.bin`. This is dracut's own rule for
    /// telling an installed kernel from a directory that merely sits beside
    /// one -- a firmware drop, or what a removed package left behind.
    no_module_dependency_index,
};

/// What the name of a `/lib/modules` entry says on its own, before anything
/// has been opened.
pub const NameVerdict = union(enum) {
    /// `.` or `..`. Excluded by the release rule anyway, and not worth
    /// reporting as a kernel a run passed over.
    ignored,
    /// Decided by the name alone; the caller reports it and moves on.
    skipped: SkipReason,
    /// The name is usable. What the entry is has to be found out by looking.
    probe,
};

/// Classifies a `/lib/modules` entry by its name.
///
/// Split from `probeVerdict` rather than taking both at once because probing
/// costs syscalls, and a caller must not be made to pay them for a name it was
/// going to refuse.
pub fn nameVerdict(name: []const u8) NameVerdict {
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return .ignored;
    if (!validKernelRelease(name)) return .{ .skipped = .invalid_release_name };
    return .probe;
}

/// What a caller found when it looked at an entry whose name was usable.
pub const Probe = enum {
    /// Could not be opened as a directory, or was gone by the time the caller
    /// looked.
    not_a_directory,
    /// A directory carrying neither dependency-index marker.
    no_dependency_index,
    /// A directory carrying at least one of them.
    module_directory,
};

/// Why the probed entry is not an installed kernel, or nothing if it is one.
pub fn probeVerdict(probe: Probe) ?SkipReason {
    return switch (probe) {
        .not_a_directory => .not_a_module_directory,
        .no_dependency_index => .no_module_dependency_index,
        .module_directory => null,
    };
}

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

test "the regeneration argv is the one both backends used to spell for themselves" {
    const argv = regenerateArgv("6.12.0-1.azl3");
    const expected = [_][]const u8{
        "/usr/bin/dracut",
        "--force",
        "--no-hostonly",
        "--tmpdir",
        "/run",
        "--kver",
        "6.12.0-1.azl3",
        "/run/zvmi-initramfs.img",
    };
    try std.testing.expectEqual(expected.len, argv.len);
    for (expected, argv) |want, got| try std.testing.expectEqualStrings(want, got);

    // The release is the only element a caller supplies, which is the property
    // that makes returning the argv by value safe.
    const other = regenerateArgv("6.6.0-rc1+");
    for (argv, other, 0..) |left, right, index| {
        if (index == 6) {
            try std.testing.expect(!std.mem.eql(u8, left, right));
        } else {
            try std.testing.expectEqualStrings(left, right);
        }
    }
}

test "the install argv moves the temporary to the path the caller names" {
    const argv = installArgv("/boot/initramfs-6.12.0-1.azl3.img");
    const expected = [_][]const u8{
        "/usr/bin/cp",
        "--remove-destination",
        "/run/zvmi-initramfs.img",
        "/boot/initramfs-6.12.0-1.azl3.img",
    };
    try std.testing.expectEqual(expected.len, argv.len);
    for (expected, argv) |want, got| try std.testing.expectEqualStrings(want, got);

    // The source is the module's own temporary rather than an argument: a
    // caller cannot ask for a different file to be published under the name
    // the digest will be taken of.
    try std.testing.expectEqualStrings(temporary_image_path, argv[2]);
}

test "the image path is the guest-visible one, with no host root in it" {
    const allocator = std.testing.allocator;
    const path = try imagePath(allocator, "6.12.0-1.azl3");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/boot/initramfs-6.12.0-1.azl3.img", path);
    try std.testing.expect(path[0] == '/');
}

test "a /lib/modules entry is classified the same way by whoever scanned it" {
    const name_cases = [_]struct {
        name: []const u8,
        expected: std.meta.Tag(NameVerdict),
        reason: ?SkipReason,
        why: []const u8,
    }{
        .{
            .name = ".",
            .expected = .ignored,
            .reason = null,
            .why = "the release rule would refuse it, but a run did not pass over a kernel",
        },
        .{
            .name = "..",
            .expected = .ignored,
            .reason = null,
            .why = "as above, and the one entry a traversal would care about",
        },
        .{
            .name = "6.12.0-1.azl3",
            .expected = .probe,
            .reason = null,
            .why = "a usable name says nothing about whether a kernel is there",
        },
        .{
            .name = ".stale",
            .expected = .skipped,
            .reason = .invalid_release_name,
            .why = "a name that could not have been requested cannot become acceptable by being discovered",
        },
        .{
            .name = "kernel modules",
            .expected = .skipped,
            .reason = .invalid_release_name,
            .why = "a space would split one dracut argument into two",
        },
    };
    for (name_cases) |case| {
        const verdict = nameVerdict(case.name);
        try std.testing.expectEqual(case.expected, std.meta.activeTag(verdict));
        if (case.reason) |reason| try std.testing.expectEqual(reason, verdict.skipped);
    }

    // All three reasons reachable as pure values, including the one the guest
    // agent never produces because its own probe cannot tell a missing marker
    // from a missing directory. The reason exists in the document either way,
    // and this is what keeps the two sides' vocabularies the same.
    try std.testing.expectEqual(
        SkipReason.not_a_module_directory,
        probeVerdict(.not_a_directory).?,
    );
    try std.testing.expectEqual(
        SkipReason.no_module_dependency_index,
        probeVerdict(.no_dependency_index).?,
    );
    try std.testing.expect(probeVerdict(.module_directory) == null);
}

test "the generator name is one string, not four" {
    try std.testing.expectEqualStrings("dracut", generator);
    try std.testing.expectEqualStrings("/usr/bin/dracut", tool_path);
    try std.testing.expect(std.mem.endsWith(u8, tool_path, generator));
    try std.testing.expectEqualStrings("modules.dep", module_dependency_markers[0]);
    try std.testing.expectEqualStrings("modules.dep.bin", module_dependency_markers[1]);
}
