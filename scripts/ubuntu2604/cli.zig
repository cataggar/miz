//! Option parsing shared by every subcommand.
//!
//! The Python this replaces used `argparse`, and the callers -- workflows and
//! shell harnesses -- were written against its behavior: `--name value` and
//! `--name=value` both work, an unknown option or a missing value is a usage
//! error that exits 2, and a repeated option keeps the last value.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const ParseError = error{ Usage, OutOfMemory };

pub const Options = struct {
    entries: std.StringHashMapUnmanaged([]const u8),
    allocator: Allocator,

    pub fn deinit(self: *Options) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn get(self: *const Options, name: []const u8) ?[]const u8 {
        return self.entries.get(name);
    }

    pub fn require(self: *const Options, name: []const u8) error{Usage}![]const u8 {
        return self.entries.get(name) orelse error.Usage;
    }

    pub fn requireInteger(self: *const Options, name: []const u8) error{Usage}!i64 {
        const text = try self.require(name);
        return std.fmt.parseInt(i64, text, 10) catch error.Usage;
    }
};

pub fn parse(
    allocator: Allocator,
    argv: []const []const u8,
    known: []const []const u8,
) ParseError!Options {
    var entries: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer entries.deinit(allocator);

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        var matched = false;
        for (known) |name| {
            if (std.mem.eql(u8, argument, name)) {
                if (index + 1 >= argv.len) return error.Usage;
                index += 1;
                try entries.put(allocator, name, argv[index]);
                matched = true;
                break;
            }
            if (argument.len > name.len and
                std.mem.startsWith(u8, argument, name) and
                argument[name.len] == '=')
            {
                try entries.put(allocator, name, argument[name.len + 1 ..]);
                matched = true;
                break;
            }
        }
        if (!matched) return error.Usage;
    }
    return .{ .entries = entries, .allocator = allocator };
}

test "both argparse spellings are accepted and the last value wins" {
    var options = try parse(
        std.testing.allocator,
        &.{ "--key", "x86_64-full", "--flavor=full", "--key", "aarch64-full" },
        &.{ "--key", "--flavor" },
    );
    defer options.deinit();
    try std.testing.expectEqualStrings("aarch64-full", try options.require("--key"));
    try std.testing.expectEqualStrings("full", try options.require("--flavor"));
    try std.testing.expectError(error.Usage, options.require("--absent"));
    try std.testing.expect(options.get("--absent") == null);
}

test "unknown options, missing values, and positionals are usage errors" {
    try std.testing.expectError(error.Usage, parse(
        std.testing.allocator,
        &.{"--unknown"},
        &.{"--key"},
    ));
    try std.testing.expectError(error.Usage, parse(
        std.testing.allocator,
        &.{"--key"},
        &.{"--key"},
    ));
    try std.testing.expectError(error.Usage, parse(
        std.testing.allocator,
        &.{"positional"},
        &.{"--key"},
    ));
}

test "integers are parsed strictly" {
    var options = try parse(
        std.testing.allocator,
        &.{ "--virtual-size=5368709120", "--bad=x" },
        &.{ "--virtual-size", "--bad" },
    );
    defer options.deinit();
    try std.testing.expectEqual(
        @as(i64, 5368709120),
        try options.requireInteger("--virtual-size"),
    );
    try std.testing.expectError(error.Usage, options.requireInteger("--bad"));
}
