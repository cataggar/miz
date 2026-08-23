//! Reading the material a declared credential names.
//!
//! The request model holds a credential as a reference -- a path on the build
//! machine or the name of one of its environment variables -- and never as
//! bytes. Something has to turn the reference into the bytes exactly once, as
//! late as possible, and hand them to whatever will use them. That is this
//! module.
//!
//! It exists as its own module because both executing backends need it and
//! they reach the package manager by different routes: `unsafe_chroot` carries
//! environment material over an anonymous pipe and reads file material inside
//! its worker, while `vm` seals the material onto a block device backed by
//! anonymous memory. The rules about what counts as usable material, how large
//! it may be, and what is left behind afterwards are properties of the
//! credential rather than of either route, so a second copy of them in the
//! second backend would be a second copy that could drift.

const std = @import("std");
const customize = @import("customize.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    CredentialSourceUnreadable,
    CredentialMaterialUnusable,
};

/// Reads what `source` names, returning an exact allocation the caller owns and
/// is responsible for zeroing.
pub fn readMaterial(
    allocator: Allocator,
    io: Io,
    environ: std.process.Environ,
    source: customize.CredentialSource,
) ![]u8 {
    switch (source) {
        .host_path => |host_path| {
            const bytes = Io.Dir.cwd().readFileAlloc(
                io,
                host_path,
                allocator,
                .limited(customize.max_credential_material_bytes),
            ) catch return error.CredentialSourceUnreadable;
            // Unconditional, not an `errdefer`: the untrimmed read is a copy of
            // the secret and does not outlive this function on either path.
            defer {
                std.crypto.secureZero(u8, bytes);
                allocator.free(bytes);
            }
            const trimmed = std.mem.trimEnd(u8, bytes, "\r\n");
            if (!validMaterial(trimmed)) return error.CredentialMaterialUnusable;
            // Copied to an exact allocation rather than resized in place: a
            // shrunk slice whose length no longer matches its allocation is
            // freed at the wrong size. The untrimmed read is zeroed, so the
            // extra copy is not an extra copy left behind.
            const material = try allocator.alloc(u8, trimmed.len);
            @memcpy(material, trimmed);
            return material;
        },
        .host_environment => |name| {
            const value = std.process.Environ.getAlloc(
                environ,
                allocator,
                name,
            ) catch return error.CredentialSourceUnreadable;
            errdefer deinitMaterial(allocator, value);
            if (!validMaterial(value)) return error.CredentialMaterialUnusable;
            return value;
        },
    }
}

/// Clears and releases material returned by `readMaterial`.
pub fn deinitMaterial(allocator: Allocator, material: []u8) void {
    scrubMaterial(material);
    allocator.free(material);
}

pub fn scrubMaterial(material: []u8) void {
    std.crypto.secureZero(u8, material);
}

/// Whether material can be written into a repository file at all.
///
/// A newline would end the INI line and let the rest be read back as
/// configuration, and a control character would be written to a file the
/// package manager parses rather than to a terminal. The bound is tight enough
/// that a misnamed source cannot spool a whole file into memory.
pub fn validMaterial(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    if (bytes.len > customize.max_credential_material_bytes) return false;
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

test "material is refused for the reasons a repository file would be misread" {
    try std.testing.expect(validMaterial("s3cr3t"));
    try std.testing.expect(!validMaterial(""));
    try std.testing.expect(!validMaterial("two\nlines"));
    try std.testing.expect(!validMaterial("bell\x07"));
    try std.testing.expect(!validMaterial("delete\x7f"));

    const oversized = [_]u8{'x'} ** (customize.max_credential_material_bytes + 1);
    try std.testing.expect(!validMaterial(&oversized));
}

test "environment material is copied from immutable storage" {
    const block = [_:null]?[*:0]const u8{
        "VMIZ_TEST_CREDENTIAL=s3cr3t-from-read-only-storage",
    };
    const environ = std.process.Environ{ .block = .{ .slice = &block } };

    const material = try readMaterial(
        std.testing.allocator,
        std.testing.io,
        environ,
        .{ .host_environment = "VMIZ_TEST_CREDENTIAL" },
    );
    defer deinitMaterial(std.testing.allocator, material);

    try std.testing.expectEqualStrings("s3cr3t-from-read-only-storage", material);
    material[0] = 'S';
    try std.testing.expectEqualStrings(
        "s3cr3t-from-read-only-storage",
        std.process.Environ.getPosix(environ, "VMIZ_TEST_CREDENTIAL").?,
    );
}

test "owned material is zero after scrubbing" {
    var material = "s3cr3t".*;
    scrubMaterial(&material);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** material.len), &material);
}
