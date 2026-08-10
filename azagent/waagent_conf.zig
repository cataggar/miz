//! Minimal `/etc/waagent.conf` reader: parses the same simple file format
//! and path real `waagent` uses, but only recognizes and honors a small,
//! explicit whitelist of keys that map to things `azagent` actually
//! implements. Every other key in the file is silently ignored -- this is
//! a deliberate middle ground, not full `waagent.conf` compatibility (see
//! issue #112's naming decision and `azagent/main.zig`'s module doc
//! comment: `azagent` does not aim for config/CLI/binary compatibility
//! with real `waagent`). See issue #125.
//!
//! Format, verified against upstream's `ConfigurationProvider.load`:
//! one `Key.Name=value` pair per line; a line starting with `#` is a
//! full-line comment; within a value, everything from the first `#`
//! onward is also stripped (an inline trailing comment), then surrounding
//! whitespace/quotes are trimmed; boolean ("switch") values are `y`/`Y`
//! (true) or `n`/`N` (false); a value of the literal string `None` is
//! treated as absent. Unrecognized/unparseable values fall back to the
//! existing default rather than erroring, matching upstream's own
//! tolerant `get`/`get_switch`/`get_int` -- there is no `ParseError`: an
//! unparseable file is just a file with no recognized settings.
//!
//! Reference: `azurelinuxagent/common/conf.py` (Microsoft Azure Linux
//! Agent, analyzed at /work/WALinuxAgent during planning);
//! `config/mariner/waagent.conf` (the Azure Linux-shipped sample).
const std = @import("std");

/// The whitelisted settings this module recognizes, with `azagent`'s own
/// defaults (used verbatim when `/etc/waagent.conf` is absent, and as the
/// starting point overridden by any recognized key present in it).
pub const WaagentConf = struct {
    /// Matches upstream's own conservative default -- see issue #125's
    /// note on `config/mariner/waagent.conf` shipping this as `n`.
    resourcedisk_format: bool = false,
    /// `azagent` only has an ext4 writer; a recognized-but-unsupported
    /// value here (anything other than "ext4") should be logged and
    /// ignored by whatever consumes this field (#113), not honored.
    resourcedisk_filesystem: []const u8 = "ext4",
    resourcedisk_mount_point: []const u8 = "/d",
    /// Account that should own the resource disk's mount point, or `""` to
    /// leave it `root:root` (upstream `waagent`'s behavior, and the default
    /// here). Not an upstream key: the resource disk is scratch space for
    /// whoever is logged in, and a root-owned mount root means every write
    /// to it needs `sudo`.
    resourcedisk_owner: []const u8 = "",
    resourcedisk_enable_swap: bool = false,
    resourcedisk_swap_size_mb: u32 = 0,
    /// `azagent` extension: mount existing ext4 managed-data-disk
    /// partitions by stable Azure LUN at `/e` through `/z`.
    datadisk_mount: bool = false,

    /// Parses `content` (the file's raw bytes) and returns a `WaagentConf`
    /// with every recognized key applied on top of the defaults above.
    /// Pure, allocation-free, and infallible: fields are borrowed slices
    /// into `content` (caller keeps it alive as long as the result is
    /// used, matching `OvfEnv`'s existing lifetime contract in this
    /// repo), and any unparseable/unrecognized line or value is simply
    /// skipped rather than erroring.
    ///
    /// Deliberately does **not** recognize `Provisioning.Enabled`: real
    /// Azure Linux images ship `/etc/waagent.conf` with that key set to
    /// `n` by default (paired with `Provisioning.Agent=auto`, i.e. "let
    /// cloud-init handle this instead"). `azagent` never defers to
    /// cloud-init -- it always fully owns provisioning (see issue #112's
    /// explicit cloud-init-interop scope note) -- so honoring that key
    /// with upstream's semantics would silently disable `azagent` by
    /// default on every real target image, defeating its entire purpose.
    pub fn parse(content: []const u8) WaagentConf {
        var result: WaagentConf = .{};

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            const kv = parseLine(raw_line) orelse continue;

            if (std.mem.eql(u8, kv.key, "ResourceDisk.Format")) {
                if (parseSwitch(kv.value)) |v| result.resourcedisk_format = v;
            } else if (std.mem.eql(u8, kv.key, "ResourceDisk.Filesystem")) {
                if (kv.value) |v| result.resourcedisk_filesystem = v;
            } else if (std.mem.eql(u8, kv.key, "ResourceDisk.MountPoint")) {
                if (kv.value) |v| result.resourcedisk_mount_point = v;
            } else if (std.mem.eql(u8, kv.key, "ResourceDisk.Owner")) {
                if (kv.value) |v| result.resourcedisk_owner = v;
            } else if (std.mem.eql(u8, kv.key, "ResourceDisk.EnableSwap")) {
                if (parseSwitch(kv.value)) |v| result.resourcedisk_enable_swap = v;
            } else if (std.mem.eql(u8, kv.key, "ResourceDisk.SwapSizeMB")) {
                if (kv.value) |v| {
                    if (std.fmt.parseInt(u32, v, 10)) |n| {
                        result.resourcedisk_swap_size_mb = n;
                    } else |_| {}
                }
            } else if (std.mem.eql(u8, kv.key, "DataDisk.Mount")) {
                if (parseSwitch(kv.value)) |v| result.datadisk_mount = v;
            }
            // Every other key is recognized as a valid line but simply
            // has no effect -- matches upstream's own permissive
            // behavior (unknown keys are stored but never consulted).
        }

        return result;
    }
};

const KeyValue = struct {
    key: []const u8,
    /// `null` for a value of the literal string `None` (treated as
    /// explicitly absent/unset, matching upstream).
    value: ?[]const u8,
};

/// Parses one line of `waagent.conf` content (no trailing `\n`). Returns
/// `null` for blank lines, full-line comments (`#` as the first
/// non-whitespace character), and lines with no `=`.
fn parseLine(line: []const u8) ?KeyValue {
    const trimmed_line = std.mem.trim(u8, line, " \t\r");
    if (trimmed_line.len == 0 or trimmed_line[0] == '#') return null;

    const eq = std.mem.indexOfScalar(u8, trimmed_line, '=') orelse return null;
    const key = std.mem.trim(u8, trimmed_line[0..eq], " \t");
    if (key.len == 0) return null;

    var value_part = trimmed_line[eq + 1 ..];
    if (std.mem.indexOfScalar(u8, value_part, '#')) |comment_start| {
        value_part = value_part[0..comment_start];
    }
    const value = std.mem.trim(u8, value_part, " \t\"");

    if (std.mem.eql(u8, value, "None")) return .{ .key = key, .value = null };
    return .{ .key = key, .value = value };
}

/// `y`/`Y` -> `true`, `n`/`N` -> `false`, anything else (including a
/// `None`/absent value) -> `null` (caller keeps its existing default).
fn parseSwitch(value: ?[]const u8) ?bool {
    const v = value orelse return null;
    if (v.len != 1) return null;
    return switch (v[0]) {
        'y', 'Y' => true,
        'n', 'N' => false,
        else => null,
    };
}

test "parseLine skips blank lines and full-line comments" {
    try std.testing.expectEqual(@as(?KeyValue, null), parseLine(""));
    try std.testing.expectEqual(@as(?KeyValue, null), parseLine("   "));
    try std.testing.expectEqual(@as(?KeyValue, null), parseLine("# a comment"));
    try std.testing.expectEqual(@as(?KeyValue, null), parseLine("  # indented comment"));
}

test "parseLine skips lines with no =" {
    try std.testing.expectEqual(@as(?KeyValue, null), parseLine("not a key value line"));
}

test "parseLine splits key=value and trims whitespace" {
    const kv = parseLine("ResourceDisk.Format=y").?;
    try std.testing.expectEqualStrings("ResourceDisk.Format", kv.key);
    try std.testing.expectEqualStrings("y", kv.value.?);

    const kv2 = parseLine("  ResourceDisk.MountPoint = /mnt/resource  ").?;
    try std.testing.expectEqualStrings("ResourceDisk.MountPoint", kv2.key);
    try std.testing.expectEqualStrings("/mnt/resource", kv2.value.?);
}

test "parseLine strips an inline trailing comment from the value" {
    const kv = parseLine("ResourceDisk.Format=y # enable it").?;
    try std.testing.expectEqualStrings("y", kv.value.?);
}

test "parseLine strips surrounding quotes from the value" {
    const kv = parseLine("ResourceDisk.MountPoint=\"/mnt/resource\"").?;
    try std.testing.expectEqualStrings("/mnt/resource", kv.value.?);
}

test "parseLine treats a None value as explicitly absent" {
    const kv = parseLine("Role.StateConsumer=None").?;
    try std.testing.expectEqualStrings("Role.StateConsumer", kv.key);
    try std.testing.expectEqual(@as(?[]const u8, null), kv.value);
}

test "parseSwitch is case-insensitive and tolerates unrecognized values" {
    try std.testing.expectEqual(@as(?bool, true), parseSwitch("y"));
    try std.testing.expectEqual(@as(?bool, true), parseSwitch("Y"));
    try std.testing.expectEqual(@as(?bool, false), parseSwitch("n"));
    try std.testing.expectEqual(@as(?bool, false), parseSwitch("N"));
    try std.testing.expectEqual(@as(?bool, null), parseSwitch("maybe"));
    try std.testing.expectEqual(@as(?bool, null), parseSwitch(null));
}

test "WaagentConf.parse returns defaults for an empty document" {
    const conf = WaagentConf.parse("");
    try std.testing.expectEqual(false, conf.resourcedisk_format);
    try std.testing.expectEqualStrings("ext4", conf.resourcedisk_filesystem);
    try std.testing.expectEqualStrings("/d", conf.resourcedisk_mount_point);
    try std.testing.expectEqualStrings("", conf.resourcedisk_owner);
    try std.testing.expectEqual(false, conf.resourcedisk_enable_swap);
    try std.testing.expectEqual(@as(u32, 0), conf.resourcedisk_swap_size_mb);
    try std.testing.expectEqual(false, conf.datadisk_mount);
}

test "WaagentConf.parse applies every recognized key from a realistic document, and ignores Provisioning.Enabled" {
    const sample =
        \\# Microsoft Azure Linux Agent Configuration
        \\#
        \\Extensions.Enabled=y
        \\Provisioning.Agent=auto
        \\Role.StateConsumer=None
        \\Provisioning.Enabled=n
        \\Provisioning.DeleteRootPassword=y
        \\
        \\ResourceDisk.Format=y
        \\ResourceDisk.Filesystem=ext4
        \\ResourceDisk.MountPoint=/mnt/resource
        \\ResourceDisk.Owner=g
        \\ResourceDisk.EnableSwap=y
        \\ResourceDisk.SwapSizeMB=2048
        \\DataDisk.Mount=y
    ;
    const conf = WaagentConf.parse(sample);
    try std.testing.expectEqual(true, conf.resourcedisk_format);
    try std.testing.expectEqualStrings("ext4", conf.resourcedisk_filesystem);
    try std.testing.expectEqualStrings("/mnt/resource", conf.resourcedisk_mount_point);
    try std.testing.expectEqualStrings("g", conf.resourcedisk_owner);
    try std.testing.expectEqual(true, conf.resourcedisk_enable_swap);
    try std.testing.expectEqual(@as(u32, 2048), conf.resourcedisk_swap_size_mb);
    try std.testing.expectEqual(true, conf.datadisk_mount);
}

test "WaagentConf.parse ignores unknown keys and unparseable values" {
    const sample =
        \\Some.Unknown.Key=whatever
        \\ResourceDisk.Format=maybe
        \\ResourceDisk.SwapSizeMB=not-a-number
    ;
    const conf = WaagentConf.parse(sample);
    // Unrecognized switch/int values leave the existing default in place.
    try std.testing.expectEqual(false, conf.resourcedisk_format);
    try std.testing.expectEqual(@as(u32, 0), conf.resourcedisk_swap_size_mb);
}

// ---------------------------------------------------------------------
// Impure half: real file I/O, scoped to a caller-provided `/etc` handle.
// ---------------------------------------------------------------------

const read_limit: std.Io.Limit = .limited(64 * 1024);

/// Reads `/etc/waagent.conf` under `etc_dir` (production passes the real
/// `/etc`; tests pass a temp directory), returning its content if present
/// or `null` if the file doesn't exist. Caller owns and must free the
/// returned slice.
pub fn readWaagentConf(allocator: std.mem.Allocator, etc_dir: std.Io.Dir, io: std.Io) !?[]u8 {
    return etc_dir.readFileAlloc(io, "waagent.conf", allocator, read_limit) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

test "readWaagentConf returns null when the file is absent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);

    try std.testing.expectEqual(@as(?[]u8, null), try readWaagentConf(allocator, etc_dir, io));
}

test "readWaagentConf returns the file's content when present" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "waagent.conf", .data = "ResourceDisk.Format=y\n" });

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);

    const content = try readWaagentConf(allocator, etc_dir, io);
    defer if (content) |c| allocator.free(c);
    try std.testing.expectEqualStrings("ResourceDisk.Format=y\n", content.?);
}
