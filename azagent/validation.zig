//! Validation for untrusted account data read from `ovf-env.xml`.
//!
//! Usernames intentionally follow a conservative policy shared by common
//! Linux account tools and Azure: 1-32 bytes, a lowercase ASCII letter first,
//! then lowercase letters, digits, `_`, or `-`, with no trailing `-`. `root`
//! is reserved. Public keys must be one printable, non-empty line no larger
//! than 16 KiB and contain a plausible authorized_keys key-type/base64 pair;
//! standard options and modern OpenSSH key types remain allowed.
const std = @import("std");

pub const max_username_len = 32;
pub const max_public_key_len = 16 * 1024;

pub const UsernameError = error{InvalidUsername};
pub const PublicKeyError = error{InvalidPublicKey};

pub fn validateUsername(username: []const u8) UsernameError!void {
    if (username.len == 0 or username.len > max_username_len) return error.InvalidUsername;
    if (username[0] < 'a' or username[0] > 'z') return error.InvalidUsername;
    for (username[1..]) |c| {
        if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '_' and c != '-') {
            return error.InvalidUsername;
        }
    }
    if (username[username.len - 1] == '-') return error.InvalidUsername;
    if (std.mem.eql(u8, username, "root")) return error.InvalidUsername;
}

fn isPlausibleKeyType(field: []const u8) bool {
    if (!(std.mem.startsWith(u8, field, "ssh-") or
        std.mem.startsWith(u8, field, "ecdsa-") or
        std.mem.startsWith(u8, field, "sk-"))) return false;
    for (field) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '@' and c != '+') {
            return false;
        }
    }
    return true;
}

fn isPlausibleBase64(field: []const u8) bool {
    if (field.len < 4) return false;
    var saw_padding = false;
    for (field) |c| {
        if (c == '=') {
            saw_padding = true;
        } else {
            if (saw_padding) return false;
            if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '/') return false;
        }
    }
    return true;
}

fn isPlausibleOption(option: []const u8) bool {
    const flags = [_][]const u8{
        "cert-authority",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-user-rc",
        "no-X11-forwarding",
        "no-touch-required",
        "restrict",
        "verify-required",
    };
    for (flags) |flag| {
        if (std.mem.eql(u8, option, flag)) return true;
    }
    const values = [_][]const u8{
        "command=",
        "environment=",
        "expiry-time=",
        "from=",
        "permitlisten=",
        "permitopen=",
        "principals=",
        "tunnel=",
    };
    for (values) |prefix| {
        if (std.mem.startsWith(u8, option, prefix) and option.len > prefix.len) return true;
    }
    return false;
}

fn isPlausibleOptions(field: []const u8) bool {
    var start: usize = 0;
    var index: usize = 0;
    var quoted = false;
    var escaped = false;
    while (index <= field.len) : (index += 1) {
        if (index == field.len or (!quoted and field[index] == ',')) {
            if (!isPlausibleOption(field[start..index])) return false;
            start = index + 1;
            continue;
        }
        const c = field[index];
        if (escaped) {
            escaped = false;
        } else if (quoted and c == '\\') {
            escaped = true;
        } else if (c == '"') {
            quoted = !quoted;
        }
    }
    return !quoted and !escaped;
}

fn nextField(line: []const u8, cursor: *usize) ?[]const u8 {
    while (cursor.* < line.len and line[cursor.*] == ' ') cursor.* += 1;
    if (cursor.* == line.len) return null;

    const start = cursor.*;
    var quoted = false;
    var escaped = false;
    while (cursor.* < line.len) : (cursor.* += 1) {
        const c = line[cursor.*];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted and c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted and c == ' ') break;
    }
    if (quoted or escaped) return null;
    return line[start..cursor.*];
}

pub fn validatePublicKey(key: []const u8) PublicKeyError!void {
    if (key.len == 0 or key.len > max_public_key_len) return error.InvalidPublicKey;
    for (key) |c| {
        if (c < 0x20 or c == 0x7f) return error.InvalidPublicKey;
    }

    var cursor: usize = 0;
    var saw_options = false;
    while (nextField(key, &cursor)) |field| {
        if (!isPlausibleKeyType(field)) {
            if (saw_options or !isPlausibleOptions(field)) return error.InvalidPublicKey;
            saw_options = true;
            continue;
        }
        const blob = nextField(key, &cursor) orelse return error.InvalidPublicKey;
        if (std.mem.indexOfAny(u8, blob, "\"\\") != null or !isPlausibleBase64(blob)) {
            return error.InvalidPublicKey;
        }
        return;
    }
    return error.InvalidPublicKey;
}

test "username policy accepts conservative Linux Azure names" {
    try validateUsername("g");
    try validateUsername("azure_user-01");
    try validateUsername(&@as([max_username_len:0]u8, @splat("a"[0])));
}

test "username policy rejects unsafe invalid and overlong names" {
    for (&[_][]const u8{
        "",
        "root",
        "../admin",
        "admin/user",
        "Admin",
        "_admin",
        "admin-",
        "admin:name",
        "admin\nextra",
        "admin\x00extra",
        &@as([(max_username_len + 1):0]u8, @splat("a"[0])),
    }) |username| {
        try std.testing.expectError(error.InvalidUsername, validateUsername(username));
    }
}

test "public key policy accepts options and modern key types" {
    try validatePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@example");
    try validatePublicKey("restrict,command=\"echo diagnostic only\" sk-ssh-ed25519@openssh.com AAAAFakeBlob== comment");
    try validatePublicKey("cert-authority ecdsa-sha2-nistp256-cert-v01@openssh.com AAAACertBlob==");
}

test "public key policy rejects injection and malformed content" {
    for (&[_][]const u8{
        "",
        "comment only",
        "# ssh-ed25519 AAAA",
        "garbage ssh-ed25519 AAAA",
        "restrict extra ssh-ed25519 AAAA",
        "ssh-ed25519",
        "ssh-ed25519 not*base64",
        "ssh-ed25519 AAAA\ncommand=\"id\"",
        "ssh-ed25519 AAAA\r",
        "ssh-ed25519 AAAA\x00suffix",
        "ssh-ed25519\tAAAA",
        "command=\"unterminated ssh-ed25519 AAAA",
        "ssh-ed25519 AA==AA",
        &@as([(max_public_key_len + 1):0]u8, @splat("x"[0])),
    }) |key| {
        try std.testing.expectError(error.InvalidPublicKey, validatePublicKey(key));
    }
}
