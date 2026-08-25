//! Disk image format identifiers and (de)serialization helpers shared across
//! the library and the CLI. Mirrors qemu-img's `-f`/`-O` format names where
//! practical, e.g. `vpc` is qemu's name for this format; we accept both `vhd`
//! and `vpc` as aliases since `vhd` is the far more common spelling.

const std = @import("std");

pub const Format = enum {
    raw,
    vhd,
    vhdx,
    qcow2,

    pub fn parseName(name: []const u8) ?Format {
        if (std.ascii.eqlIgnoreCase(name, "raw")) return .raw;
        if (std.ascii.eqlIgnoreCase(name, "vhd")) return .vhd;
        if (std.ascii.eqlIgnoreCase(name, "vpc")) return .vhd;
        if (std.ascii.eqlIgnoreCase(name, "vhdx")) return .vhdx;
        if (std.ascii.eqlIgnoreCase(name, "qcow2")) return .qcow2;
        return null;
    }

    pub fn displayName(self: Format) []const u8 {
        return switch (self) {
            .raw => "raw",
            .vhd => "vhd",
            .vhdx => "vhdx",
            .qcow2 => "qcow2",
        };
    }
};

test "Format.parseName accepts vhd and vpc aliases" {
    try std.testing.expectEqual(Format.vhd, Format.parseName("vhd").?);
    try std.testing.expectEqual(Format.vhd, Format.parseName("VPC").?);
    try std.testing.expectEqual(Format.raw, Format.parseName("RAW").?);
    try std.testing.expectEqual(Format.vhdx, Format.parseName("vhdx").?);
    try std.testing.expectEqual(Format.qcow2, Format.parseName("qcow2").?);
}
