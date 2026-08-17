//! Shared `-O`/`-o` output option helpers for the CLI commands.

const std = @import("std");
const vmiz = @import("vmiz");

/// Explains why an `-O`/`-o` combination was refused. Shared so that every
/// command describes the same constraint with the same words.
pub fn describeOutputError(err: vmiz.output.SpecError) []const u8 {
    return switch (err) {
        error.CompressionRequiresRawFormat => "compressed output is produced while the image is written, and only raw is written in a single forward pass (use raw.gz or raw.zst)",
        error.FormatRequiresSeekableOutput => "stdout cannot be seeked backwards, and vhd (trailing footer), vhdx (BAT), and qcow2 (L1 and refcount tables) all amend metadata after the data (use raw, raw.gz, or raw.zst)",
        error.CompressionLevelNotSupportedForZstd => "--compress-level applies to gzip only; the in-tree zstd encoder has a single fixed strategy",
        error.CompressionLevelOutOfRange => "--compress-level must be 1 (fastest) through 9 (smallest)",
    };
}

/// Parses a qemu-img-style `-o` option string (currently only
/// `subformat=fixed|dynamic` is recognized, matching qemu-img's `-f vpc -o
/// subformat=...`). Returns `null` and prints a diagnostic on the first
/// unrecognized key or value.
pub fn parseVhdCreateOptions(opt_string: []const u8) ?vmiz.CreateOptions {
    var options = vmiz.CreateOptions{};
    var it = std.mem.splitScalar(u8, opt_string, ',');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse {
            std.debug.print("create: malformed -o option '{s}' (expected key=value)\n", .{pair});
            return null;
        };
        const key = pair[0..eq];
        const value = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "subformat")) {
            if (std.mem.eql(u8, value, "fixed")) {
                options.vhd_subformat = .fixed;
            } else if (std.mem.eql(u8, value, "dynamic")) {
                options.vhd_subformat = .dynamic;
            } else {
                std.debug.print("create: unknown subformat '{s}' (expected fixed or dynamic)\n", .{value});
                return null;
            }
        } else {
            std.debug.print("create: unknown -o option '{s}'\n", .{key});
            return null;
        }
    }
    return options;
}
