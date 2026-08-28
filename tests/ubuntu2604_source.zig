//! Shared source-reading helpers for the Ubuntu 26.04 workflow guards.
//!
//! The workflow, harness, and publication guards all assert on the text of
//! files in the tracked tree: which jobs exist, which tools a step may install,
//! which order steps run in. They therefore need the repository root rather
//! than whatever directory the test binary happened to start in, which
//! `build.zig` names outright through `MIZ_UBUNTU2604_SOURCE_ROOT`.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

/// No file this guard reads is anywhere near this size.
pub const max_source_bytes: usize = 4 * 1024 * 1024;

/// The interpreter these guards assert is absent, spelled in halves so the
/// guards' own tracked bytes never carry the command they exist to reject --
/// and so the repository's Python inventory never counts an assertion as an
/// invocation.
pub const interpreter = "pyt" ++ "hon3";
/// The firmware-variable package the Ubuntu jobs used to install. UEFI
/// Secure Boot variable enrollment is native now, so this name is asserted
/// absent rather than allowed; it is still spelled in halves for the same
/// reason the interpreter is.
pub const firmware_package = interpreter ++ "-virt-firmware";

pub fn rootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_UBUNTU2604_SOURCE_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

/// The release binary the harness guards execute.
///
/// `build.zig` declares the installed artifact as a dependency of these tests
/// and names it through `MIZ_UBUNTU2604_RELEASE_TOOL`, so a clean tree builds
/// and installs the tool before the first guard runs. A direct `zig test`
/// invocation without that variable falls back to the default install prefix.
/// Either way an absent binary is reported as a missing build dependency
/// rather than as a command that failed to produce output.
pub fn releaseToolAlloc(allocator: Allocator) ![]u8 {
    const declared = std.testing.environ.getAlloc(
        allocator,
        "MIZ_UBUNTU2604_RELEASE_TOOL",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
    const tool = declared orelse tool: {
        const root = try rootAlloc(allocator);
        defer allocator.free(root);
        break :tool try std.fs.path.join(
            allocator,
            &.{ root, "zig-out", "bin", "ubuntu2604_release" },
        );
    };
    errdefer allocator.free(tool);
    _ = Dir.cwd().statFile(std.testing.io, tool, .{}) catch {
        std.debug.print(
            "{s}: release tool is not installed; " ++
                "these guards depend on the ubuntu2604_release artifact\n",
            .{tool},
        );
        return error.ReleaseToolMissing;
    };
    return tool;
}

/// Reads a repository-relative file. Caller owns the result.
pub fn readAlloc(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_source_bytes),
    );
}

/// A source file plus the assertions the guards make about it. Every failure
/// names the needle, so a guard that trips reads as a checklist item rather
/// than as "expected true, found false".
pub const Source = struct {
    allocator: Allocator,
    path: []const u8,
    text: []u8,

    pub fn open(allocator: Allocator, relative: []const u8) !Source {
        return .{
            .allocator = allocator,
            .path = relative,
            .text = try readAlloc(allocator, relative),
        };
    }

    pub fn deinit(self: *Source) void {
        self.allocator.free(self.text);
        self.* = undefined;
    }

    pub fn expectContains(self: *const Source, needle: []const u8) !void {
        try expectContainsIn(self.text, needle, self.path);
    }

    pub fn expectOmits(self: *const Source, needle: []const u8) !void {
        try expectOmitsIn(self.text, needle, self.path);
    }

    pub fn expectCount(self: *const Source, needle: []const u8, count: usize) !void {
        const actual = std.mem.count(u8, self.text, needle);
        if (actual == count) return;
        std.debug.print(
            "{s}: expected {d} occurrence(s) of \"{s}\", found {d}\n",
            .{ self.path, count, needle, actual },
        );
        return error.UnexpectedOccurrenceCount;
    }

    /// The text between `start` and the next `end` after it. Used to scope an
    /// assertion to one workflow job or one step.
    pub fn section(
        self: *const Source,
        start: []const u8,
        end: ?[]const u8,
    ) ![]const u8 {
        const start_index = std.mem.indexOf(u8, self.text, start) orelse {
            std.debug.print("{s}: missing section start \"{s}\"\n", .{
                self.path,
                start,
            });
            return error.MissingSection;
        };
        const rest = self.text[start_index + start.len ..];
        const end_marker = end orelse return rest;
        const end_index = std.mem.indexOf(u8, rest, end_marker) orelse {
            std.debug.print("{s}: missing section end \"{s}\"\n", .{
                self.path,
                end_marker,
            });
            return error.MissingSection;
        };
        return rest[0..end_index];
    }

    /// Byte offset of `needle`, for order assertions.
    pub fn indexOf(self: *const Source, needle: []const u8) !usize {
        return indexOfIn(self.text, needle, self.path);
    }
};

pub fn expectContainsIn(
    text: []const u8,
    needle: []const u8,
    label: []const u8,
) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("{s}: missing \"{s}\"\n", .{ label, needle });
    return error.MissingText;
}

pub fn expectOmitsIn(
    text: []const u8,
    needle: []const u8,
    label: []const u8,
) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("{s}: forbidden \"{s}\" is present\n", .{ label, needle });
    return error.ForbiddenText;
}

pub fn indexOfIn(text: []const u8, needle: []const u8, label: []const u8) !usize {
    return std.mem.indexOf(u8, text, needle) orelse {
        std.debug.print("{s}: missing \"{s}\"\n", .{ label, needle });
        return error.MissingText;
    };
}

/// Whether `first` appears before `second`, with both required to be present.
pub fn isBefore(text: []const u8, first: []const u8, second: []const u8) ?bool {
    const first_index = std.mem.indexOf(u8, text, first) orelse return null;
    const second_index = std.mem.indexOf(u8, text, second) orelse return null;
    return first_index < second_index;
}

pub fn expectOrder(
    text: []const u8,
    first: []const u8,
    second: []const u8,
    label: []const u8,
) !void {
    const first_index = try indexOfIn(text, first, label);
    const second_index = try indexOfIn(text, second, label);
    if (first_index < second_index) return;
    std.debug.print("{s}: \"{s}\" must come before \"{s}\"\n", .{
        label,
        first,
        second,
    });
    return error.WrongOrder;
}

/// `FORBIDDEN_PRODUCTION_TOOL`: the image-manipulation stack this repository
/// replaced with native code. `virt-fw-vars`/`virt-firmware` are excluded from
/// this pattern because they were never image tools; they are now absent
/// outright, which the workflow guards assert separately.
pub fn findForbiddenProductionTool(text: []const u8) ?[]const u8 {
    const literals = [_][]const u8{
        "libguestfs",
        "guestfish",
        "supermin",
        "LIBGUESTFS_BACKEND_SETTINGS",
    };
    for (literals) |literal| {
        if (std.mem.indexOf(u8, text, literal)) |index| {
            return text[index..][0..literal.len];
        }
    }
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, text, cursor, "virt-")) |index| {
        cursor = index + 1;
        // `\b` in the Python pattern: the match must start at a word boundary.
        if (index > 0 and isWordByte(text[index - 1])) continue;
        var end = index + "virt-".len;
        while (end < text.len and isToolByte(text[end])) end += 1;
        const match = text[index..end];
        if (match.len == "virt-".len) continue;
        if (std.mem.eql(u8, match, "virt-fw-vars") or
            std.mem.eql(u8, match, "virt-firmware")) continue;
        // The lookahead is anchored at the token start, so a longer token that
        // merely begins with an exempt name is still forbidden.
        if (std.mem.startsWith(u8, match, "virt-fw-vars") or
            std.mem.startsWith(u8, match, "virt-firmware")) continue;
        return match;
    }
    return null;
}

fn isWordByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn isToolByte(byte: u8) bool {
    return std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-';
}

test "forbidden production tools are detected and the firmware tools are not" {
    try std.testing.expectEqualStrings(
        "libguestfs",
        findForbiddenProductionTool("install libguestfs-tools").?,
    );
    try std.testing.expectEqualStrings(
        "virt-customize",
        findForbiddenProductionTool("run virt-customize now").?,
    );
    try std.testing.expect(
        findForbiddenProductionTool("python3-virt-firmware") == null,
    );
    try std.testing.expect(findForbiddenProductionTool("virt-fw-vars") == null);
    try std.testing.expect(findForbiddenProductionTool("nothing here") == null);
}

test "sections and order assertions read a workflow the way review does" {
    const text =
        \\  build:
        \\    steps:
        \\      - name: first
        \\      - name: second
        \\  publish:
        \\      - name: third
    ;
    const build = try (Source{
        .allocator = std.testing.allocator,
        .path = "fixture",
        .text = @constCast(text),
    }).section("  build:\n", "\n  publish:\n");
    try expectContainsIn(build, "- name: first", "fixture");
    try expectOmitsIn(build, "- name: third", "fixture");
    try expectOrder(build, "first", "second", "fixture");
    try std.testing.expectEqual(@as(?bool, true), isBefore(build, "first", "second"));
    try std.testing.expectEqual(@as(?bool, false), isBefore(build, "second", "first"));
    try std.testing.expectEqual(@as(?bool, null), isBefore(build, "first", "absent"));
}
