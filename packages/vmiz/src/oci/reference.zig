const std = @import("std");
const content = @import("content.zig");

pub const ParseMode = enum {
    source,
    destination,
    list_tags,
};

pub const Selection = union(enum) {
    tag: []const u8,
    digest: content.Digest,
};

pub const RegistryReference = struct {
    authority: []const u8,
    repository: []const u8,
    selection: ?Selection,
};

pub const LayoutReference = struct {
    path: []const u8,
    selection: ?Selection,
};

pub const Reference = union(enum) {
    registry: RegistryReference,
    layout: LayoutReference,
};

pub const Error = error{
    InvalidReference,
    InvalidAuthority,
    InvalidRepository,
    InvalidTag,
    InvalidLayoutPath,
    InvalidLayoutName,
    MissingSelection,
    UnexpectedSelection,
} || content.Error;

pub fn parse(text: []const u8, mode: ParseMode) Error!Reference {
    if (std.mem.startsWith(u8, text, "docker://")) return .{ .registry = try parseRegistry(text["docker://".len..], mode) };
    if (std.mem.startsWith(u8, text, "oci:")) {
        if (mode == .list_tags) return error.InvalidReference;
        return .{ .layout = try parseLayout(text["oci:".len..], mode) };
    }
    return error.InvalidReference;
}

fn parseRegistry(value: []const u8, mode: ParseMode) Error!RegistryReference {
    if (hasForbiddenUriSyntax(value)) return error.InvalidReference;
    const slash = std.mem.indexOfScalar(u8, value, '/') orelse return error.InvalidReference;
    const authority = value[0..slash];
    try validateAuthority(authority);
    const repository_and_selection = value[slash + 1 ..];
    const split = try splitRepositorySelection(repository_and_selection);
    try validateRepository(split.repository);
    try validateRegistrySelectionForMode(split.selection, mode);
    return .{ .authority = authority, .repository = split.repository, .selection = split.selection };
}

fn parseLayout(value: []const u8, mode: ParseMode) Error!LayoutReference {
    if (value.len == 0 or hasForbiddenUriSyntax(value)) return error.InvalidLayoutPath;
    const split = try splitLayoutSelection(value);
    if (split.repository.len == 0) return error.InvalidLayoutPath;
    if (split.selection) |selection| switch (selection) {
        .tag => |name| try validateLayoutName(name),
        .digest => {},
    };
    try validateLayoutSelectionForMode(split.selection, mode);
    return .{ .path = split.repository, .selection = split.selection };
}

const Split = struct {
    repository: []const u8,
    selection: ?Selection,
};

fn splitRepositorySelection(value: []const u8) Error!Split {
    if (value.len == 0) return error.InvalidRepository;
    if (std.mem.indexOfScalar(u8, value, '@')) |at| {
        if (std.mem.indexOfScalarPos(u8, value, at + 1, '@') != null) return error.InvalidReference;
        return .{ .repository = value[0..at], .selection = .{ .digest = try content.Digest.parse(value[at + 1 ..]) } };
    }
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return .{ .repository = value, .selection = null };
    const slash = std.mem.lastIndexOfScalar(u8, value, '/');
    if (slash != null and colon < slash.?) return .{ .repository = value, .selection = null };
    const tag = value[colon + 1 ..];
    try validateTag(tag);
    return .{ .repository = value[0..colon], .selection = .{ .tag = tag } };
}

fn splitLayoutSelection(value: []const u8) Error!Split {
    if (std.mem.indexOfScalar(u8, value, '@')) |at| {
        if (std.mem.indexOfScalarPos(u8, value, at + 1, '@') != null) return error.InvalidReference;
        return .{ .repository = value[0..at], .selection = .{ .digest = try content.Digest.parse(value[at + 1 ..]) } };
    }
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return .{ .repository = value, .selection = null };
    if (isWindowsDriveColon(value, colon)) return .{ .repository = value, .selection = null };
    return .{ .repository = value[0..colon], .selection = .{ .tag = value[colon + 1 ..] } };
}

fn validateRegistrySelectionForMode(selection: ?Selection, mode: ParseMode) Error!void {
    switch (mode) {
        .source, .destination => if (selection == null) return error.MissingSelection,
        .list_tags => if (selection != null) return error.UnexpectedSelection,
    }
}

fn validateLayoutSelectionForMode(selection: ?Selection, mode: ParseMode) Error!void {
    switch (mode) {
        .source, .destination => {},
        .list_tags => if (selection != null) return error.UnexpectedSelection,
    }
}

fn validateAuthority(authority: []const u8) Error!void {
    if (authority.len == 0 or std.mem.indexOfScalar(u8, authority, '@') != null) return error.InvalidAuthority;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidAuthority;
        if (close == 1) return error.InvalidAuthority;
        _ = std.Io.net.IpAddress.parseIp6(authority[1..close], 0) catch return error.InvalidAuthority;
        if (close + 1 < authority.len) {
            if (authority[close + 1] != ':') return error.InvalidAuthority;
            try validatePort(authority[close + 2 ..]);
        }
        return;
    }
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = if (colon) |index| authority[0..index] else authority;
    if (colon) |index| try validatePort(authority[index + 1 ..]);
    if (host.len == 0) return error.InvalidAuthority;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label[0] == '-' or label[label.len - 1] == '-') return error.InvalidAuthority;
        for (label) |byte| {
            if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-') return error.InvalidAuthority;
        }
    }
}

fn validatePort(port: []const u8) Error!void {
    if (port.len == 0 or port.len > 5) return error.InvalidAuthority;
    var number: u32 = 0;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidAuthority;
        number = number * 10 + (byte - '0');
    }
    if (number == 0 or number > 65535) return error.InvalidAuthority;
}

fn validateRepository(repository: []const u8) Error!void {
    if (repository.len == 0 or repository[0] == '/' or repository[repository.len - 1] == '/') return error.InvalidRepository;
    var segments = std.mem.splitScalar(u8, repository, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or
            (!std.ascii.isLower(segment[0]) and !std.ascii.isDigit(segment[0])) or
            (!std.ascii.isLower(segment[segment.len - 1]) and !std.ascii.isDigit(segment[segment.len - 1]))) return error.InvalidRepository;
        var index: usize = 0;
        while (index < segment.len) {
            while (index < segment.len and (std.ascii.isLower(segment[index]) or std.ascii.isDigit(segment[index]))) : (index += 1) {}
            if (index == segment.len) break;

            switch (segment[index]) {
                '.' => index += 1,
                '_' => {
                    index += 1;
                    if (index < segment.len and segment[index] == '_') index += 1;
                },
                '-' => while (index < segment.len and segment[index] == '-') : (index += 1) {},
                else => return error.InvalidRepository,
            }
            if (index == segment.len or !std.ascii.isLower(segment[index]) and !std.ascii.isDigit(segment[index])) {
                return error.InvalidRepository;
            }
        }
    }
}

fn validateTag(tag: []const u8) Error!void {
    if (tag.len == 0 or tag.len > 128 or
        (!std.ascii.isAlphanumeric(tag[0]) and tag[0] != '_')) return error.InvalidTag;
    for (tag) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '.' and byte != '-') return error.InvalidTag;
    }
}

fn validateLayoutName(name: []const u8) Error!void {
    if (name.len == 0 or std.mem.indexOfAny(u8, name, "/\\:@") != null) return error.InvalidLayoutName;
    try validateTag(name);
}

fn hasForbiddenUriSyntax(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "?#") != null;
}

fn isWindowsDriveColon(value: []const u8, colon: usize) bool {
    return colon == 1 and value.len >= 3 and std.ascii.isAlphabetic(value[0]) and
        (value[2] == '\\' or value[2] == '/');
}

test "registry parsing is explicit and supports IPv6" {
    const reference = try parse("docker://[2001:db8::1]:5000/team/image:stable", .source);
    const registry = reference.registry;
    try std.testing.expectEqualStrings("[2001:db8::1]:5000", registry.authority);
    try std.testing.expectEqualStrings("team/image", registry.repository);
    try std.testing.expectEqualStrings("stable", registry.selection.?.tag);
    _ = try parse("docker://registry.example/team/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", .source);
}

test "reference modes reject implicit or inappropriate selectors" {
    try std.testing.expectError(error.MissingSelection, parse("docker://registry.example/team/image", .source));
    _ = try parse("docker://registry.example/team/image", .list_tags);
    try std.testing.expectError(error.UnexpectedSelection, parse("docker://registry.example/team/image:latest", .list_tags));
    _ = try parse("oci:/layout", .source);
    _ = try parse("oci:/layout", .destination);
    try std.testing.expectError(error.InvalidReference, parse("oci:/layout", .list_tags));
}

test "reference parsing rejects unsafe registry forms and supports Windows paths" {
    try std.testing.expectError(error.InvalidRepository, parse("docker://registry.example/Team/image:tag", .source));
    try std.testing.expectError(error.InvalidRepository, parse("docker://registry.example/team/image-:tag", .source));
    try std.testing.expectError(error.InvalidTag, parse("docker://registry.example/team/image:bad!", .source));
    try std.testing.expectError(error.InvalidAuthority, parse("docker://user@registry.example/image:tag", .source));
    try std.testing.expectError(error.InvalidAuthority, parse("docker://registry..example/image:tag", .source));
    try std.testing.expectError(error.InvalidAuthority, parse("docker://registry.-example/image:tag", .source));
    try std.testing.expectError(error.InvalidAuthority, parse("docker://[2001:db8:::1]/image:tag", .source));
    try std.testing.expectError(error.InvalidRepository, parse("docker://registry.example/team/foo._bar:tag", .source));
    try std.testing.expectError(error.InvalidRepository, parse("docker://registry.example/team/foo-.bar:tag", .source));
    try std.testing.expectError(error.InvalidReference, parse("docker://registry.example/image:tag?x=1", .source));
    try std.testing.expectError(error.InvalidDigest, parse("docker://registry.example/image@sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789", .source));
    const reference = try parse("oci:C:\\images\\layout:root", .source);
    try std.testing.expectEqualStrings("C:\\images\\layout", reference.layout.path);
    try std.testing.expectEqualStrings("root", reference.layout.selection.?.tag);
}
