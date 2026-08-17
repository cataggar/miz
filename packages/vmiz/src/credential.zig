//! Reading the material a declared credential names.
//!
//! The request model holds a credential as a reference -- a path on the build
//! machine or the name of one of its environment variables -- and never as
//! bytes. Something has to turn the reference into the bytes exactly once, as
//! late as possible, and hand them to whatever will use them. That is this
//! module.
//!
//! It exists as its own module because both executing backends need it and
//! they reach the package manager by different routes: `unsafe_chroot` renders
//! a repository file inside a worker that has already re-execed as root, and
//! `vm` seals the material onto a block device backed by anonymous memory. The
//! rules about what counts as usable material, how large it may be, and what is
//! left behind afterwards are properties of the credential rather than of
//! either route, so a second copy of them in the second backend would be a
//! second copy that could drift.

const std = @import("std");
const builtin = @import("builtin");

const customize = @import("customize.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    CredentialSourceUnreadable,
    CredentialMaterialUnusable,
};

/// Reads what `source` names, returning an exact allocation the caller owns and
/// is responsible for zeroing.
///
/// `scrub` overwrites a consumed environment variable in the calling process's
/// own environment. It is a parameter rather than a rule because the two
/// backends stand in different places. The chroot worker is PID 1 in its
/// namespace and mounts a real `proc` inside the target root, so a variable
/// left in its environment is readable through `/proc/1/environ` by every
/// package scriptlet and dracut module that runs afterwards -- target-supplied
/// code running as root, after the repository file has been deleted. The VM
/// backend runs in the caller's own process and gives the guest no view of it,
/// so scrubbing there would erase a variable belonging to the program that
/// called the library, to protect against a reader that does not exist.
pub fn readMaterial(
    allocator: Allocator,
    io: Io,
    environ: std.process.Environ,
    source: customize.CredentialSource,
    scrub: bool,
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
                @memset(bytes, 0);
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
            errdefer {
                @memset(value, 0);
                allocator.free(value);
            }
            if (!validMaterial(value)) return error.CredentialMaterialUnusable;
            if (scrub) scrubEnvironmentValue(environ, name);
            return value;
        },
    }
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

pub fn scrubEnvironmentValue(environ: std.process.Environ, name: []const u8) void {
    if (builtin.os.tag == .windows) return;
    const value = std.process.Environ.getPosix(environ, name) orelse return;
    @memset(@constCast(value), 0);
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
