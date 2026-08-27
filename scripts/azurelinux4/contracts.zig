//! Release contracts for the Azure Linux 4 image matrix.
//!
//! Native port of the validation half of `scripts/azurelinux4_release.py`.
//! Everything here is a pure function over already-parsed JSON, so the whole
//! contract can be exercised against constructed documents rather than only
//! through a filesystem. The command layer in `commands.zig` adds the reads,
//! the digests, and the writes.
//!
//! Two properties are load bearing and are the reason this is a faithful port
//! rather than a re-derivation:
//!
//! * every failure keeps the exact operator-facing sentence its Python
//!   predecessor produced, because CI logs and reviewers match on that text;
//!   and
//! * every digest is taken over the same canonical bytes, because digests
//!   published by earlier releases were computed over exactly those bytes.

const std = @import("std");

const release = @import("../release/root.zig");

const Allocator = std.mem.Allocator;
const contract = release.contract;
const json_document = release.json_document;

pub const Diagnostic = contract.Diagnostic;
pub const Value = std.json.Value;
pub const ObjectMap = std.json.ObjectMap;

/// One entry of the release matrix: the exact architecture, flavor, and asset
/// name a candidate key is allowed to carry. `EXPECTED` in the Python.
pub const Entry = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset_name: []const u8,

    /// The architecture-specific removable-media fallback path a signed UKI
    /// set must contain.
    pub fn fallbackUkiPath(self: Entry) []const u8 {
        return if (std.mem.eql(u8, self.architecture, "x86_64"))
            "EFI/BOOT/BOOTX64.EFI"
        else
            "EFI/BOOT/BOOTAA64.EFI";
    }
};

/// `RELEASE_ORDER`: the publication order, which is also the order the release
/// notes table rows appear in.
pub const release_order = [_]Entry{
    .{
        .key = "x86_64-full",
        .architecture = "x86_64",
        .flavor = "full",
        .asset_name = "AzureLinux-4.0-x86_64.qcow2",
    },
    .{
        .key = "aarch64-full",
        .architecture = "aarch64",
        .flavor = "full",
        .asset_name = "AzureLinux-4.0-aarch64.qcow2",
    },
    .{
        .key = "x86_64-core",
        .architecture = "x86_64",
        .flavor = "core",
        .asset_name = "AzureLinux-4.0-x86_64.core.qcow2",
    },
    .{
        .key = "aarch64-core",
        .architecture = "aarch64",
        .flavor = "core",
        .asset_name = "AzureLinux-4.0-aarch64.core.qcow2",
    },
};

pub fn lookup(key: []const u8) ?Entry {
    for (release_order) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry;
    }
    return null;
}

/// `sorted(AZURE_CONTRACTS)`: the exact result set an Azure acceptance run
/// must record. Kept sorted so it is emitted and compared without allocating.
pub const azure_contracts = [_][]const u8{
    "agent-ready",
    "kernel-lockdown",
    "key-only-ssh",
    "managed-data-disk",
    "matching-architecture-gen2",
    "module-signatures",
    "reboot-reconnect",
    "resource-disk",
    "root-growth",
    "runtime-flavor-identity",
    "secure-boot",
    "signed-uki",
    "trusted-launch",
    "uefi-db-signer",
    "vtpm",
};

/// Text markers of a PEM-armored private key of any kind.
pub const private_key_pem_markers = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

pub const gallery_signature_template = "MicrosoftUefiCertificateAuthorityTemplate";

pub const ContractError = error{
    InvalidSchema,
    InvalidKey,
    IdentityMismatch,
    InvalidUefiSettings,
    InvalidSigningProvenance,
    InvalidBase64,
};

pub const Error = ContractError ||
    contract.DigestError ||
    contract.CommitError ||
    error{OutOfMemory};

// ---------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------

pub fn stringOrNull(value: ?Value) ?[]const u8 {
    const present = value orelse return null;
    return switch (present) {
        .string => |text| text,
        else => null,
    };
}

/// The object a value holds, by value: `std.json.ObjectMap` is a handle onto
/// memory the parsed document owns, so copying the handle is cheap and keeps
/// no pointer into the temporary this switch captured.
pub fn objectOrNull(value: ?Value) ?ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |map| map,
        else => null,
    };
}

pub fn arrayOrNull(value: ?Value) ?[]const Value {
    const present = value orelse return null;
    return switch (present) {
        .array => |items| items.items,
        else => null,
    };
}

/// `type(value) is not int` in the Python: a JSON boolean or float is not an
/// integer, and neither is an integer too large to be one.
pub fn integerOrNull(value: ?Value) ?i64 {
    const present = value orelse return null;
    return switch (present) {
        .integer => |number| number,
        else => null,
    };
}

/// Whether `value` is exactly the string `text`. Mirrors `x.get(k) != "text"`.
pub fn isString(value: ?Value, text: []const u8) bool {
    const actual = stringOrNull(value) orelse return false;
    return std.mem.eql(u8, actual, text);
}

/// Whether `value` is exactly the integer `number`. Python compares `!= 1`,
/// which is false for `True` as well, since `True == 1`; JSON keeps booleans
/// in their own variant, so a boolean never satisfies this.
pub fn isInteger(value: ?Value, number: i64) bool {
    const actual = integerOrNull(value) orelse return false;
    return actual == number;
}

/// Whether the object's key set is exactly `keys`. `set(document) != {...}` in
/// the Python: an extra key is as much a rejection as a missing one.
pub fn hasExactKeys(map: ObjectMap, keys: []const []const u8) bool {
    if (map.count() != keys.len) return false;
    for (keys) |key| {
        if (!map.contains(key)) return false;
    }
    return true;
}

/// Deep JSON equality, used where the Python compares two parsed documents
/// with `==`. Numbers are compared within their own variant: a release
/// document that spells a size as a float is a different document.
pub fn jsonEql(left: Value, right: Value) bool {
    return switch (left) {
        .null => right == .null,
        .bool => |flag| right == .bool and right.bool == flag,
        .integer => |number| right == .integer and right.integer == number,
        .float => |number| right == .float and right.float == number,
        .number_string => |text| right == .number_string and
            std.mem.eql(u8, right.number_string, text),
        .string => |text| right == .string and std.mem.eql(u8, right.string, text),
        .array => |items| blk: {
            if (right != .array) break :blk false;
            const other = right.array.items;
            if (items.items.len != other.len) break :blk false;
            for (items.items, other) |item, counterpart| {
                if (!jsonEql(item, counterpart)) break :blk false;
            }
            break :blk true;
        },
        .object => |map| blk: {
            if (right != .object) break :blk false;
            if (map.count() != right.object.count()) break :blk false;
            var iterator = map.iterator();
            while (iterator.next()) |pair| {
                const counterpart = right.object.get(pair.key_ptr.*) orelse
                    break :blk false;
                if (!jsonEql(pair.value_ptr.*, counterpart)) break :blk false;
            }
            break :blk true;
        },
    };
}

pub const Pair = struct { []const u8, Value };

/// Builds a JSON object. The canonical writer sorts keys, so the order these
/// pairs are given in is a readability choice only.
pub fn object(allocator: Allocator, pairs: []const Pair) Allocator.Error!Value {
    var map: ObjectMap = .empty;
    try map.ensureTotalCapacity(allocator, pairs.len);
    for (pairs) |pair| map.putAssumeCapacity(pair[0], pair[1]);
    return .{ .object = map };
}

pub fn array(allocator: Allocator, items: []const Value) Allocator.Error!Value {
    var list: std.json.Array = .init(allocator);
    try list.ensureTotalCapacity(items.len);
    for (items) |item| list.appendAssumeCapacity(item);
    return .{ .array = list };
}

pub fn str(text: []const u8) Value {
    return .{ .string = text };
}

pub fn int(number: i64) Value {
    return .{ .integer = number };
}

/// The `{value!r}` spelling a Python diagnostic would have produced. Only the
/// shapes those diagnostics can actually reach are rendered exactly; anything
/// else is named by its JSON type, which still tells an operator what arrived.
pub const Repr = struct {
    buffer: [96]u8 = undefined,
    length: usize = 0,

    pub fn slice(self: *const Repr) []const u8 {
        return self.buffer[0..self.length];
    }

    pub fn of(value: ?Value) Repr {
        var result: Repr = .{};
        const present = value orelse {
            result.write("None", .{});
            return result;
        };
        switch (present) {
            .null => result.write("None", .{}),
            .bool => |flag| result.write("{s}", .{if (flag) "True" else "False"}),
            .integer => |number| result.write("{d}", .{number}),
            .number_string => |text| result.write("{s}", .{text}),
            .float => |number| result.write("{d}", .{number}),
            .string => |text| result.write("'{s}'", .{text}),
            .array => result.write("[...]", .{}),
            .object => result.write("{{...}}", .{}),
        }
        return result;
    }

    fn write(self: *Repr, comptime fmt: []const u8, args: anytype) void {
        const written = std.fmt.bufPrint(&self.buffer, fmt, args) catch
            self.buffer[0..];
        self.length = written.len;
    }
};

/// The `{value!r}` spelling of a whole document, for the diagnostics that
/// repeat the input they rejected. Python's `repr` is reproduced exactly for
/// the shapes these documents hold -- dicts, lists, strings, integers,
/// booleans, and `None` -- because the point of those diagnostics is that an
/// operator can compare the text against what the service returned.
pub fn writePythonRepr(out: *std.Io.Writer, value: Value) std.Io.Writer.Error!void {
    switch (value) {
        .null => try out.writeAll("None"),
        .bool => |flag| try out.writeAll(if (flag) "True" else "False"),
        .integer => |number| try out.print("{d}", .{number}),
        .number_string => |text| try out.writeAll(text),
        .float => |number| try out.print("{d}", .{number}),
        .string => |text| try writePythonString(out, text),
        .array => |items| {
            try out.writeAll("[");
            for (items.items, 0..) |item, index| {
                if (index != 0) try out.writeAll(", ");
                try writePythonRepr(out, item);
            }
            try out.writeAll("]");
        },
        .object => |map| {
            try out.writeAll("{");
            var iterator = map.iterator();
            var index: usize = 0;
            while (iterator.next()) |pair| : (index += 1) {
                if (index != 0) try out.writeAll(", ");
                try writePythonString(out, pair.key_ptr.*);
                try out.writeAll(": ");
                try writePythonRepr(out, pair.value_ptr.*);
            }
            try out.writeAll("}");
        },
    }
}

fn writePythonString(out: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    try out.writeAll("'");
    for (text) |character| switch (character) {
        '\\' => try out.writeAll("\\\\"),
        '\'' => try out.writeAll("\\'"),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        else => try out.writeByte(character),
    };
    try out.writeAll("'");
}

/// `writePythonRepr` into a caller-owned string.
pub fn pythonReprAlloc(allocator: Allocator, value: Value) Allocator.Error![]u8 {
    var text: std.Io.Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    // An allocating writer only fails when its allocation does.
    writePythonRepr(&text.writer, value) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

/// `base64.b64decode(text, validate=True)`: strict alphabet, strict padding.
pub fn decodeBase64Alloc(allocator: Allocator, text: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    decoder.decode(bytes, text) catch return error.InvalidBase64;
    return bytes;
}

/// `base64.b64encode(bytes).decode("ascii")`.
pub fn encodeBase64Alloc(allocator: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const encoder = std.base64.standard.Encoder;
    const text = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    errdefer allocator.free(text);
    std.debug.assert(encoder.encode(text, bytes).len == text.len);
    return text;
}

// ---------------------------------------------------------------------------
// Private key material
// ---------------------------------------------------------------------------

const Tlv = struct { tag: u8, start: usize, end: usize };

/// One DER tag-length-value header, bounded by `limit`. A header that claims
/// more than the enclosing structure holds is not a TLV at all.
fn readTlv(data: []const u8, offset: usize, limit: usize) ?Tlv {
    if (offset + 2 > limit) return null;
    const tag = data[offset];
    var length: usize = data[offset + 1];
    var cursor = offset + 2;
    if (length & 0x80 != 0) {
        const length_bytes = length & 0x7F;
        if (length_bytes == 0 or length_bytes > 4 or cursor + length_bytes > limit) {
            return null;
        }
        length = 0;
        for (data[cursor..][0..length_bytes]) |byte| {
            length = (length << 8) | byte;
        }
        cursor += length_bytes;
    }
    const end = cursor + length;
    if (end > limit) return null;
    return .{ .tag = tag, .start = cursor, .end = end };
}

/// Whether a DER private key structure starts at `offset`.
///
/// Two shapes count. `SEQUENCE { INTEGER version, ... }` covers PKCS#1, SEC1,
/// PKCS#8 and PKCS#12, whose versions are 0, 1, and 3. `SEQUENCE { SEQUENCE {
/// OID ... }, OCTET STRING }` ending exactly at the outer sequence covers an
/// EncryptedPrivateKeyInfo, which carries no version of its own.
fn derPrivateKeyAt(data: []const u8, offset: usize) bool {
    const root = readTlv(data, offset, data.len) orelse return false;
    if (root.tag != 0x30) return false;
    const first = readTlv(data, root.start, root.end) orelse return false;
    if (first.tag == 0x02) {
        const version = data[first.start..first.end];
        return std.mem.eql(u8, version, "\x00") or
            std.mem.eql(u8, version, "\x01") or
            std.mem.eql(u8, version, "\x03");
    }

    const second = readTlv(data, first.end, root.end) orelse return false;
    if (first.tag != 0x30 or second.tag != 0x04 or second.end != root.end) {
        return false;
    }
    const algorithm_oid = readTlv(data, first.start, first.end) orelse return false;
    return algorithm_oid.tag == 0x06;
}

/// Whether `data` carries private key material in any form this repository's
/// provenance could plausibly leak it: PEM armor, or a DER structure anywhere
/// in the file -- including embedded in an otherwise textual build log.
pub fn containsPrivateKey(data: []const u8) bool {
    for (private_key_pem_markers) |marker| {
        if (std.mem.indexOf(u8, data, marker) != null) return true;
    }

    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, data, cursor, 0x30)) |candidate| {
        if (derPrivateKeyAt(data, candidate)) return true;
        cursor = candidate + 1;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Document identity
// ---------------------------------------------------------------------------

/// `validate_identity`: the schema, type, key, architecture, flavor, asset
/// name, and source commit a candidate or acceptance document must carry.
pub fn validateIdentity(
    map: *const ObjectMap,
    expected_type: []const u8,
    key: ?[]const u8,
    source_commit: ?[]const u8,
    diagnostic: *Diagnostic,
) Error!Entry {
    if (!isInteger(map.get("schema"), 1) or !isString(map.get("type"), expected_type)) {
        return diagnostic.fail(
            error.InvalidSchema,
            "invalid {s} schema",
            .{expected_type},
        );
    }
    const actual_key = stringOrNull(map.get("key")) orelse {
        const repr = Repr.of(map.get("key"));
        return diagnostic.fail(
            error.InvalidKey,
            "invalid candidate key: {s}",
            .{repr.slice()},
        );
    };
    const entry = lookup(actual_key) orelse {
        const repr = Repr.of(map.get("key"));
        return diagnostic.fail(
            error.InvalidKey,
            "invalid candidate key: {s}",
            .{repr.slice()},
        );
    };
    if (key) |expected_key| {
        if (!std.mem.eql(u8, actual_key, expected_key)) return diagnostic.fail(
            error.InvalidKey,
            "candidate key mismatch: expected {s}, got {s}",
            .{ expected_key, actual_key },
        );
    }
    if (!isString(map.get("architecture"), entry.architecture)) return diagnostic.fail(
        error.IdentityMismatch,
        "{s}: architecture mismatch",
        .{actual_key},
    );
    if (!isString(map.get("flavor"), entry.flavor)) return diagnostic.fail(
        error.IdentityMismatch,
        "{s}: flavor mismatch",
        .{actual_key},
    );
    if (!isString(map.get("asset_name"), entry.asset_name)) return diagnostic.fail(
        error.IdentityMismatch,
        "{s}: asset name mismatch",
        .{actual_key},
    );
    const actual_commit = try contract.requireCommit(
        map.get("source_commit"),
        "source_commit",
        diagnostic,
    );
    if (source_commit) |expected_commit| {
        if (!std.mem.eql(u8, actual_commit, expected_commit)) return diagnostic.fail(
            error.IdentityMismatch,
            "{s}: source commit mismatch",
            .{actual_key},
        );
    }
    return entry;
}

// ---------------------------------------------------------------------------
// Azure custom UEFI settings
// ---------------------------------------------------------------------------

/// `validate_azure_uefi_settings`: the gallery version must keep the Microsoft
/// template and add exactly one x509 db entry, whose base64 is canonical and
/// whose bytes are the release signing certificate.
pub fn validateAzureUefiSettings(
    allocator: Allocator,
    settings: ?Value,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) Error!Value {
    const map = objectOrNull(settings) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI settings have an unexpected shape",
        .{},
    );
    if (!hasExactKeys(map, &.{ "signatureTemplateNames", "additionalSignatures" })) {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI settings have an unexpected shape",
            .{},
        );
    }
    const templates = arrayOrNull(map.get("signatureTemplateNames"));
    const retains_template = templates != null and
        templates.?.len == 1 and
        isString(templates.?[0], gallery_signature_template);
    if (!retains_template) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI settings do not retain the Microsoft template",
        .{},
    );
    const additional = objectOrNull(map.get("additionalSignatures")) orelse
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI additional signatures are invalid",
            .{},
        );
    if (!hasExactKeys(additional, &.{"db"})) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI additional signatures are invalid",
        .{},
    );
    const encoded = dbCertificateBase64(additional.get("db")) orelse
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI db signature is invalid",
            .{},
        );

    const certificate = decodeBase64Alloc(allocator, encoded) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI certificate is not canonical base64",
            .{},
        ),
    };
    defer allocator.free(certificate);
    if (!std.mem.eql(u8, &release.digest.hexBytes(certificate), certificate_sha256)) {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI certificate fingerprint mismatch",
            .{},
        );
    }
    return settings.?;
}

fn dbCertificateBase64(db: ?Value) ?[]const u8 {
    const entries = arrayOrNull(db) orelse return null;
    if (entries.len != 1) return null;
    const signature = objectOrNull(entries[0]) orelse return null;
    if (!isString(signature.get("type"), "x509")) return null;
    if (!hasExactKeys(signature, &.{ "type", "value" })) return null;
    const values = arrayOrNull(signature.get("value")) orelse return null;
    if (values.len != 1) return null;
    return stringOrNull(values[0]);
}

/// `gallery_uefi_settings`: the settings a gallery document carries, or null
/// when any level of the path is absent or not an object.
pub fn galleryUefiSettings(document: *const ObjectMap) ?Value {
    const properties = objectOrNull(document.get("properties")) orelse return null;
    const security_profile = objectOrNull(properties.get("securityProfile")) orelse
        return null;
    return security_profile.get("uefiSettings");
}

/// `validate_azure_gallery_uefi_settings`: the request must carry custom
/// settings, and a response that reports settings at all must report the same
/// ones. A response that omits them is allowed -- boot validation is what
/// proves enrollment -- but a differing response is not.
pub fn validateAzureGalleryUefiSettings(
    allocator: Allocator,
    request: *const ObjectMap,
    response: *const ObjectMap,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) Error!Value {
    const request_uefi = galleryUefiSettings(request);
    const response_uefi = galleryUefiSettings(response);
    const request_map = objectOrNull(request_uefi) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure gallery request omitted custom UEFI settings",
        .{},
    );
    _ = request_map;
    if (response_uefi) |actual| {
        if (!jsonEql(actual, request_uefi.?)) return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure gallery version returned different custom UEFI settings",
            .{},
        );
    }
    _ = try validateAzureUefiSettings(
        allocator,
        request_uefi,
        certificate_sha256,
        diagnostic,
    );
    return request_uefi.?;
}

/// `has_exact_contracts`: the acceptance result set must be exactly the
/// contracts this release requires -- no omission, no duplicate, no extra.
pub fn hasExactContracts(value: ?Value) bool {
    const items = arrayOrNull(value) orelse return false;
    if (items.len != azure_contracts.len) return false;
    var seen = [_]bool{false} ** azure_contracts.len;
    for (items) |item| {
        const text = stringOrNull(item) orelse return false;
        var matched = false;
        for (azure_contracts, 0..) |name, index| {
            if (std.mem.eql(u8, name, text)) {
                seen[index] = true;
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    for (seen) |flag| {
        if (!flag) return false;
    }
    return true;
}

/// The contract result set as a JSON array, in the sorted order the Python
/// emits.
pub fn azureContractsValue(allocator: Allocator) Allocator.Error!Value {
    var list: std.json.Array = .init(allocator);
    try list.ensureTotalCapacity(azure_contracts.len);
    for (azure_contracts) |name| list.appendAssumeCapacity(str(name));
    return .{ .array = list };
}

// ---------------------------------------------------------------------------
// UKI signing provenance
// ---------------------------------------------------------------------------

/// `^https://[a-z0-9.-]+\.codesigning\.azure\.net$`.
pub fn isArtifactSigningEndpoint(text: []const u8) bool {
    const prefix = "https://";
    const suffix = ".codesigning.azure.net";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    if (!std.mem.endsWith(u8, text, suffix)) return false;
    const host = text[prefix.len .. text.len - suffix.len];
    if (host.len == 0) return false;
    for (host) |character| switch (character) {
        'a'...'z', '0'...'9', '.', '-' => {},
        else => return false,
    };
    return true;
}

/// `^[A-Za-z0-9._-]{1,128}$`.
pub fn isArtifactSigningResource(text: []const u8) bool {
    if (text.len == 0 or text.len > 128) return false;
    for (text) |character| switch (character) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// `UUID_RE`: the canonical 8-4-4-4-12 hexadecimal spelling, either case.
pub fn isUuid(text: []const u8) bool {
    const groups = [_]usize{ 8, 4, 4, 4, 12 };
    var index: usize = 0;
    for (groups, 0..) |length, group| {
        if (group != 0) {
            if (index >= text.len or text[index] != '-') return false;
            index += 1;
        }
        if (index + length > text.len) return false;
        for (text[index..][0..length]) |character| switch (character) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return false,
        };
        index += length;
    }
    return index == text.len;
}

/// The binding a validated signing provenance document produces. It is
/// recorded in `candidate.json` and re-derived on every later read, so the two
/// can be compared for exact equality.
pub const SigningBinding = struct {
    certificate_sha256: []const u8,
    certificate_der_base64: []const u8,
    fallback_uki_sha256: []const u8,
    provider_name: []const u8,
    provider_endpoint: []const u8,
    provider_account: []const u8,
    provider_profile: []const u8,
    signing_certificate_sha256: []const u8,
    signer_mode: []const u8,
    provenance_path: []const u8,

    /// The exact JSON object the Python `validate_signing_provenance` returns.
    pub fn toValue(self: SigningBinding, allocator: Allocator) Allocator.Error!Value {
        const provider = try object(allocator, &.{
            .{ "name", str(self.provider_name) },
            .{ "endpoint", str(self.provider_endpoint) },
            .{ "account", str(self.provider_account) },
            .{ "profile", str(self.provider_profile) },
        });
        return object(allocator, &.{
            .{ "certificate_sha256", str(self.certificate_sha256) },
            .{ "certificate_der_base64", str(self.certificate_der_base64) },
            .{ "fallback_uki_sha256", str(self.fallback_uki_sha256) },
            .{ "provider", provider },
            .{ "signing_certificate_sha256", str(self.signing_certificate_sha256) },
            .{ "signer_mode", str(self.signer_mode) },
            .{ "provenance_path", str(self.provenance_path) },
        });
    }
};

/// The file name a flavor/architecture pair's signing provenance must use.
pub fn signingProvenanceName(
    buffer: []u8,
    architecture: []const u8,
    flavor: []const u8,
) []const u8 {
    return std.fmt.bufPrint(
        buffer,
        "uki-signing-{s}-{s}.json",
        .{ flavor, architecture },
    ) catch unreachable;
}

/// Longest `uki-signing-<flavor>-<architecture>.json` this matrix can produce.
pub const signing_provenance_name_capacity = 64;

/// `validate_signing_provenance` minus the read: every field of the signing
/// document, the provider identity, and the per-UKI signature bindings.
///
/// The fallback binary is the subject of the last two checks: it must be
/// byte-identical to one of the named UKIs *and* carry that UKI's signing
/// operation, so a fallback cannot be a separately signed binary that merely
/// hashes the same.
pub fn bindSigningProvenance(
    allocator: Allocator,
    document: *const ObjectMap,
    entry: Entry,
    provenance_path: []const u8,
    diagnostic: *Diagnostic,
) Error!SigningBinding {
    if (!isInteger(document.get("schema"), 1) or
        !isString(document.get("type"), "miz-uki-signing"))
    {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "invalid UKI signing provenance schema",
            .{},
        );
    }
    if (!isString(document.get("architecture"), entry.architecture) or
        !isString(document.get("flavor"), entry.flavor))
    {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "UKI signing provenance architecture/flavor mismatch",
            .{},
        );
    }
    if (!isString(document.get("signer_mode"), "external-command")) {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "release UKIs were not signed by the external provider",
            .{},
        );
    }
    const certificate_sha256 = try contract.requireSha256(
        document.get("certificate_sha256"),
        "UKI signing certificate fingerprint",
        diagnostic,
    );
    const certificate_der_base64 = stringOrNull(document.get("certificate_der_base64")) orelse
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "canonical DER UKI signing certificate is absent",
            .{},
        );
    const certificate_der = decodeBase64Alloc(
        allocator,
        certificate_der_base64,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.InvalidSigningProvenance,
            "canonical DER UKI signing certificate is not valid base64",
            .{},
        ),
    };
    defer allocator.free(certificate_der);
    if (certificate_der.len == 0 or
        !std.mem.eql(u8, &release.digest.hexBytes(certificate_der), certificate_sha256))
    {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "canonical DER UKI signing certificate fingerprint mismatch",
            .{},
        );
    }
    if (!isString(document.get("signature_verification"), "success")) {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "UKI signature verification did not explicitly succeed",
            .{},
        );
    }
    const details = stringOrNull(document.get("certificate_details")) orelse "";
    if (details.len == 0) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "UKI signing certificate details are absent",
        .{},
    );

    const provider = objectOrNull(document.get("provider")) orelse
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "Artifact Signing provider identity is absent",
            .{},
        );
    if (!hasExactKeys(provider, &.{
        "name",
        "endpoint",
        "account",
        "profile",
        "signing_certificate_sha256",
    })) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "Artifact Signing provider identity is absent",
        .{},
    );
    if (!isString(provider.get("name"), "azure-artifact-signing")) {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "unexpected UKI signing provider",
            .{},
        );
    }
    const endpoint = stringOrNull(provider.get("endpoint")) orelse "";
    const account = stringOrNull(provider.get("account")) orelse "";
    const profile = stringOrNull(provider.get("profile")) orelse "";
    if (!isArtifactSigningEndpoint(endpoint) or
        !isArtifactSigningResource(account) or
        !isArtifactSigningResource(profile))
    {
        return diagnostic.fail(
            error.InvalidSigningProvenance,
            "invalid Artifact Signing provider identity",
            .{},
        );
    }
    const signing_certificate_sha256 = try contract.requireSha256(
        provider.get("signing_certificate_sha256"),
        "Artifact Signing leaf certificate fingerprint",
        diagnostic,
    );

    const files = arrayOrNull(document.get("files")) orelse &.{};
    if (files.len < 2) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "UKI signing provenance file bindings are absent",
        .{},
    );

    const fallback_path = entry.fallbackUkiPath();
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    var named: std.StringHashMapUnmanaged(std.StringHashMapUnmanaged(void)) = .empty;
    defer {
        var iterator = named.valueIterator();
        while (iterator.next()) |operations| operations.deinit(allocator);
        named.deinit(allocator);
    }
    var fallback_digest: ?[]const u8 = null;
    var fallback_operation: ?[]const u8 = null;

    for (files) |record| {
        const fields = objectOrNull(record) orelse return diagnostic.fail(
            error.InvalidSigningProvenance,
            "invalid UKI signing file record",
            .{},
        );
        const uki_path = stringOrNull(fields.get("path")) orelse
            return diagnostic.fail(
                error.InvalidSigningProvenance,
                "invalid or duplicate UKI signing path",
                .{},
            );
        if (seen.contains(uki_path)) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "invalid or duplicate UKI signing path",
            .{},
        );
        const is_fallback = std.mem.eql(u8, uki_path, fallback_path);
        if (!is_fallback and !isNamedUkiPath(uki_path)) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "unexpected UKI signing path: {s}",
            .{uki_path},
        );
        try seen.put(allocator, uki_path, {});

        var label: [std.fs.max_path_bytes + 32]u8 = undefined;
        const unsigned = try contract.requireSha256(
            fields.get("unsigned_sha256"),
            labelFor(&label, uki_path, "unsigned UKI digest"),
            diagnostic,
        );
        const signed = try contract.requireSha256(
            fields.get("signed_sha256"),
            labelFor(&label, uki_path, "signed UKI digest"),
            diagnostic,
        );
        const finalized = try contract.requireSha256(
            fields.get("finalized_sha256"),
            labelFor(&label, uki_path, "finalized UKI digest"),
            diagnostic,
        );
        if (std.mem.eql(u8, unsigned, signed) or !std.mem.eql(u8, signed, finalized)) {
            return diagnostic.fail(
                error.InvalidSigningProvenance,
                "{s}: invalid signed/finalized UKI digest binding",
                .{uki_path},
            );
        }
        const signed_bytes = integerOrNull(fields.get("signed_bytes")) orelse 0;
        if (signed_bytes <= 0) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "{s}: invalid signed UKI size",
            .{uki_path},
        );
        const operation_id = stringOrNull(fields.get("signing_operation_id")) orelse "";
        if (!isUuid(operation_id)) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "{s}: invalid Artifact Signing operation ID",
            .{uki_path},
        );
        if (!isString(
            fields.get("signing_certificate_sha256"),
            signing_certificate_sha256,
        )) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "{s}: Artifact Signing leaf fingerprint mismatch",
            .{uki_path},
        );

        if (is_fallback) {
            fallback_digest = signed;
            fallback_operation = operation_id;
        } else {
            const slot = try named.getOrPut(allocator, signed);
            if (!slot.found_existing) slot.value_ptr.* = .empty;
            try slot.value_ptr.put(allocator, operation_id, {});
        }
    }

    const digest = fallback_digest orelse return diagnostic.fail(
        error.InvalidSigningProvenance,
        "fallback UKI is not byte-identical to a named signed UKI",
        .{},
    );
    const operations = named.getPtr(digest) orelse return diagnostic.fail(
        error.InvalidSigningProvenance,
        "fallback UKI is not byte-identical to a named signed UKI",
        .{},
    );
    if (!operations.contains(fallback_operation.?)) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "fallback UKI does not retain its named UKI signing operation",
        .{},
    );

    return .{
        .certificate_sha256 = certificate_sha256,
        .certificate_der_base64 = certificate_der_base64,
        .fallback_uki_sha256 = digest,
        .provider_name = "azure-artifact-signing",
        .provider_endpoint = endpoint,
        .provider_account = account,
        .provider_profile = profile,
        .signing_certificate_sha256 = signing_certificate_sha256,
        .signer_mode = "external-command",
        .provenance_path = provenance_path,
    };
}

fn isNamedUkiPath(path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, "EFI/Linux/")) return false;
    if (path.len < 4) return false;
    const extension = path[path.len - 4 ..];
    return std.ascii.eqlIgnoreCase(extension, ".efi");
}

fn labelFor(buffer: []u8, path: []const u8, suffix: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s} {s}", .{ path, suffix }) catch buffer;
}

// ---------------------------------------------------------------------------
// Provenance records
// ---------------------------------------------------------------------------

/// One provenance file as it is recorded in `candidate.json`.
pub const ProvenanceRecord = struct {
    path: []const u8,
    bytes: u64,
    sha256: []const u8,

    pub fn toValue(self: ProvenanceRecord, allocator: Allocator) Allocator.Error!Value {
        return object(allocator, &.{
            .{ "path", str(self.path) },
            .{ "bytes", int(@intCast(self.bytes)) },
            .{ "sha256", str(self.sha256) },
        });
    }
};

pub fn provenanceRecordsValue(
    allocator: Allocator,
    records: []const ProvenanceRecord,
) Allocator.Error!Value {
    var list: std.json.Array = .init(allocator);
    try list.ensureTotalCapacity(records.len);
    for (records) |record| {
        list.appendAssumeCapacity(try record.toValue(allocator));
    }
    return .{ .array = list };
}

/// `provenance_digest`: SHA-256 over
/// `json.dumps(records, separators=(",", ":"), sort_keys=True)`.
pub fn provenanceDigest(
    allocator: Allocator,
    records: Value,
) json_document.CanonicalError!release.digest.Hex {
    const encoded = try json_document.canonicalAlloc(allocator, records, .compact);
    defer allocator.free(encoded);
    return release.digest.hexBytes(encoded);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn parse(text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, std.testing.allocator, text, .{});
}

test "the release matrix is the exact published four" {
    try std.testing.expectEqual(@as(usize, 4), release_order.len);
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-x86_64.qcow2",
        lookup("x86_64-full").?.asset_name,
    );
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-aarch64.core.qcow2",
        lookup("aarch64-core").?.asset_name,
    );
    try std.testing.expectEqual(@as(?Entry, null), lookup("riscv64-full"));
    try std.testing.expectEqualStrings(
        "EFI/BOOT/BOOTX64.EFI",
        lookup("x86_64-core").?.fallbackUkiPath(),
    );
    try std.testing.expectEqualStrings(
        "EFI/BOOT/BOOTAA64.EFI",
        lookup("aarch64-full").?.fallbackUkiPath(),
    );
}

test "the Azure contract set is sorted, unique, and complete" {
    try std.testing.expectEqual(@as(usize, 15), azure_contracts.len);
    var previous: []const u8 = "";
    for (azure_contracts) |name| {
        try std.testing.expect(std.mem.lessThan(u8, previous, name));
        previous = name;
    }

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const value = try azureContractsValue(arena.allocator());
    try std.testing.expect(hasExactContracts(value));

    // A duplicate that keeps the length, a missing entry, and an extra entry
    // are all rejected.
    var duplicated = try parse(
        \\["agent-ready", "agent-ready", "key-only-ssh", "kernel-lockdown",
        \\ "managed-data-disk", "matching-architecture-gen2",
        \\ "module-signatures", "reboot-reconnect", "resource-disk",
        \\ "root-growth", "runtime-flavor-identity", "secure-boot",
        \\ "signed-uki", "trusted-launch", "uefi-db-signer"]
    );
    defer duplicated.deinit();
    try std.testing.expect(!hasExactContracts(duplicated.value));
    try std.testing.expect(!hasExactContracts(null));
    try std.testing.expect(!hasExactContracts(str("vtpm")));
}

test "private key material is detected in PEM and DER shapes" {
    try std.testing.expect(containsPrivateKey("-----BEGIN PRIVATE KEY-----\nsecret\n"));
    try std.testing.expect(containsPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----"));
    // PKCS#8 version 0.
    try std.testing.expect(containsPrivateKey(
        "\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00",
    ));
    // EncryptedPrivateKeyInfo: algorithm sequence then an octet string.
    try std.testing.expect(containsPrivateKey(
        "\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
    ));
    // The same structure embedded in otherwise textual output.
    try std.testing.expect(containsPrivateKey(
        "diagnostic output\n\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
    ));
    // PKCS#12 container: version 3.
    try std.testing.expect(containsPrivateKey(
        "\x30\x08\x02\x01\x03\x30\x03\x06\x01\x2a",
    ));

    try std.testing.expect(!containsPrivateKey(""));
    try std.testing.expect(!containsPrivateKey("x86_64-full\n"));
    try std.testing.expect(!containsPrivateKey("-----BEGIN CERTIFICATE-----\nMIIB\n"));
    // A truncated header claiming more than it holds is not a key.
    try std.testing.expect(!containsPrivateKey("\x30\x82\x7f\xff\x02\x01\x00"));
    // A sequence whose first element is an unrelated integer version.
    try std.testing.expect(!containsPrivateKey("\x30\x03\x02\x01\x05"));
}

test "identity validation names each mismatch the way the Python did" {
    var diagnostic: Diagnostic = .{};
    var good = try parse(
        \\{"schema": 1, "type": "azurelinux4-candidate", "key": "x86_64-full",
        \\ "architecture": "x86_64", "flavor": "full",
        \\ "asset_name": "AzureLinux-4.0-x86_64.qcow2",
        \\ "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    );
    defer good.deinit();
    const entry = try validateIdentity(
        &good.value.object,
        "azurelinux4-candidate",
        "x86_64-full",
        "a" ** 40,
        &diagnostic,
    );
    try std.testing.expectEqualStrings("x86_64-full", entry.key);

    try std.testing.expectError(error.InvalidKey, validateIdentity(
        &good.value.object,
        "azurelinux4-candidate",
        "aarch64-core",
        null,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "candidate key mismatch: expected aarch64-core, got x86_64-full",
        diagnostic.message(),
    );

    try std.testing.expectError(error.IdentityMismatch, validateIdentity(
        &good.value.object,
        "azurelinux4-candidate",
        null,
        "b" ** 40,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "x86_64-full: source commit mismatch",
        diagnostic.message(),
    );

    try std.testing.expectError(error.InvalidSchema, validateIdentity(
        &good.value.object,
        "azurelinux4-azure-acceptance",
        null,
        null,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid azurelinux4-azure-acceptance schema",
        diagnostic.message(),
    );
}

test "identity validation rejects unknown and non-string keys" {
    var diagnostic: Diagnostic = .{};
    var unknown = try parse(
        \\{"schema": 1, "type": "azurelinux4-candidate", "key": "riscv64-full"}
    );
    defer unknown.deinit();
    try std.testing.expectError(error.InvalidKey, validateIdentity(
        &unknown.value.object,
        "azurelinux4-candidate",
        null,
        null,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid candidate key: 'riscv64-full'",
        diagnostic.message(),
    );

    var absent = try parse(
        \\{"schema": 1, "type": "azurelinux4-candidate"}
    );
    defer absent.deinit();
    try std.testing.expectError(error.InvalidKey, validateIdentity(
        &absent.value.object,
        "azurelinux4-candidate",
        null,
        null,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid candidate key: None",
        diagnostic.message(),
    );

    var numeric = try parse(
        \\{"schema": 1, "type": "azurelinux4-candidate", "key": 7}
    );
    defer numeric.deinit();
    try std.testing.expectError(error.InvalidKey, validateIdentity(
        &numeric.value.object,
        "azurelinux4-candidate",
        null,
        null,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid candidate key: 7",
        diagnostic.message(),
    );

    // A boolean `schema` is not the integer 1, the way `True == 1` would have
    // been in Python if the value had not stayed in its own JSON variant.
    var boolean = try parse(
        \\{"schema": true, "type": "azurelinux4-candidate", "key": "x86_64-full"}
    );
    defer boolean.deinit();
    try std.testing.expectError(error.InvalidSchema, validateIdentity(
        &boolean.value.object,
        "azurelinux4-candidate",
        null,
        null,
        &diagnostic,
    ));
}

const test_certificate = "miz test certificate DER";

fn uefiSettingsJson(allocator: Allocator, certificate: []const u8) ![]u8 {
    const encoded = try encodeBase64Alloc(allocator, certificate);
    defer allocator.free(encoded);
    return std.fmt.allocPrint(allocator,
        \\{{"signatureTemplateNames": ["{s}"],
        \\  "additionalSignatures": {{"db": [{{"type": "x509", "value": ["{s}"]}}]}}}}
    , .{ gallery_signature_template, encoded });
}

test "Azure UEFI settings bind the canonical DER certificate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const fingerprint = release.digest.hexBytes(test_certificate);
    const text = try uefiSettingsJson(allocator, test_certificate);
    var settings = try parse(text);
    defer settings.deinit();
    _ = try validateAzureUefiSettings(
        allocator,
        settings.value,
        &fingerprint,
        &diagnostic,
    );

    const other = try uefiSettingsJson(allocator, "different");
    var wrong = try parse(other);
    defer wrong.deinit();
    try std.testing.expectError(error.InvalidUefiSettings, validateAzureUefiSettings(
        allocator,
        wrong.value,
        &fingerprint,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "Azure custom UEFI certificate fingerprint mismatch",
        diagnostic.message(),
    );
}

test "Azure UEFI settings reject every malformed shape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    const fingerprint = release.digest.hexBytes(test_certificate);

    const cases = [_]struct { text: []const u8, message: []const u8 }{
        .{
            .text = "[]",
            .message = "Azure custom UEFI settings have an unexpected shape",
        },
        .{
            .text =
            \\{"signatureTemplateNames": [], "additionalSignatures": {"db": []},
            \\ "extra": 1}
            ,
            .message = "Azure custom UEFI settings have an unexpected shape",
        },
        .{
            .text =
            \\{"signatureTemplateNames": ["NoSignatureTemplate"],
            \\ "additionalSignatures": {"db": []}}
            ,
            .message = "Azure custom UEFI settings do not retain the Microsoft template",
        },
        .{
            .text =
            \\{"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
            \\ "additionalSignatures": {"db": [], "dbx": []}}
            ,
            .message = "Azure custom UEFI additional signatures are invalid",
        },
        .{
            .text =
            \\{"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
            \\ "additionalSignatures": {"db": [{"type": "sha256", "value": ["AA=="]}]}}
            ,
            .message = "Azure custom UEFI db signature is invalid",
        },
        .{
            .text =
            \\{"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
            \\ "additionalSignatures": {"db": [{"type": "x509", "value": ["not base64!"]}]}}
            ,
            .message = "Azure custom UEFI certificate is not canonical base64",
        },
    };

    for (cases) |case| {
        var parsed = try parse(case.text);
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidUefiSettings, validateAzureUefiSettings(
            allocator,
            parsed.value,
            &fingerprint,
            &diagnostic,
        ));
        try std.testing.expectEqualStrings(case.message, diagnostic.message());
    }
}

test "a gallery response may omit accepted settings but not change them" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    const fingerprint = release.digest.hexBytes(test_certificate);

    const settings = try uefiSettingsJson(allocator, test_certificate);
    const request_text = try std.fmt.allocPrint(
        allocator,
        \\{{"properties": {{"securityProfile": {{"uefiSettings": {s}}}}}}}
    ,
        .{settings},
    );
    var request = try parse(request_text);
    defer request.deinit();

    var omitted = try parse(
        \\{"properties": {"provisioningState": "Succeeded"}}
    );
    defer omitted.deinit();
    const bound = try validateAzureGalleryUefiSettings(
        allocator,
        &request.value.object,
        &omitted.value.object,
        &fingerprint,
        &diagnostic,
    );
    try std.testing.expect(jsonEql(bound, galleryUefiSettings(&request.value.object).?));

    var changed = try parse(
        \\{"properties": {"securityProfile":
        \\  {"uefiSettings": {"signatureTemplateNames": []}}}}
    );
    defer changed.deinit();
    try std.testing.expectError(
        error.InvalidUefiSettings,
        validateAzureGalleryUefiSettings(
            allocator,
            &request.value.object,
            &changed.value.object,
            &fingerprint,
            &diagnostic,
        ),
    );
    try std.testing.expectEqualStrings(
        "Azure gallery version returned different custom UEFI settings",
        diagnostic.message(),
    );

    var without = try parse(
        \\{"properties": {}}
    );
    defer without.deinit();
    try std.testing.expectError(
        error.InvalidUefiSettings,
        validateAzureGalleryUefiSettings(
            allocator,
            &without.value.object,
            &omitted.value.object,
            &fingerprint,
            &diagnostic,
        ),
    );
    try std.testing.expectEqualStrings(
        "Azure gallery request omitted custom UEFI settings",
        diagnostic.message(),
    );
}

test "provider identity shapes are accepted or rejected exactly" {
    try std.testing.expect(isArtifactSigningEndpoint("https://wus.codesigning.azure.net"));
    try std.testing.expect(!isArtifactSigningEndpoint("https://wus.codesigning.azure.net/"));
    try std.testing.expect(!isArtifactSigningEndpoint("http://wus.codesigning.azure.net"));
    try std.testing.expect(!isArtifactSigningEndpoint("https://WUS.codesigning.azure.net"));
    try std.testing.expect(!isArtifactSigningEndpoint("https://.codesigning.azure.net"));

    try std.testing.expect(isArtifactSigningResource("miz-uki"));
    try std.testing.expect(isArtifactSigningResource("a" ** 128));
    try std.testing.expect(!isArtifactSigningResource("a" ** 129));
    try std.testing.expect(!isArtifactSigningResource(""));
    try std.testing.expect(!isArtifactSigningResource("miz uki"));

    try std.testing.expect(isUuid("00000000-0000-4000-8000-000000000001"));
    try std.testing.expect(isUuid("00000000-0000-4000-8000-00000000000A"));
    try std.testing.expect(!isUuid("00000000-0000-4000-8000-00000000001"));
    try std.testing.expect(!isUuid("00000000-0000-4000-8000-000000000001 "));
    try std.testing.expect(!isUuid("000000000000400080000000000000001"));
}

const test_signing_leaf = "4" ** 64;
const test_operation_id = "00000000-0000-4000-8000-000000000001";

fn signingDocument(allocator: Allocator, options: struct {
    architecture: []const u8 = "x86_64",
    flavor: []const u8 = "full",
    signer_mode: []const u8 = "external-command",
    endpoint: []const u8 = "https://wus.codesigning.azure.net",
    fallback_signed: []const u8 = "3" ** 64,
    fallback_operation: []const u8 = test_operation_id,
    named_signed: []const u8 = "3" ** 64,
    certificate: []const u8 = test_certificate,
}) ![]u8 {
    const encoded = try encodeBase64Alloc(allocator, options.certificate);
    const fingerprint = release.digest.hexBytes(options.certificate);
    const fallback = if (std.mem.eql(u8, options.architecture, "x86_64"))
        "EFI/BOOT/BOOTX64.EFI"
    else
        "EFI/BOOT/BOOTAA64.EFI";
    return std.fmt.allocPrint(allocator,
        \\{{"schema": 1, "type": "miz-uki-signing",
        \\  "architecture": "{s}", "flavor": "{s}", "signer_mode": "{s}",
        \\  "certificate_sha256": "{s}", "certificate_der_base64": "{s}",
        \\  "certificate_details": "subject=CN=miz test signer",
        \\  "provider": {{"name": "azure-artifact-signing", "endpoint": "{s}",
        \\    "account": "cataggar", "profile": "miz-uki",
        \\    "signing_certificate_sha256": "{s}"}},
        \\  "signature_verification": "success",
        \\  "files": [
        \\    {{"path": "EFI/Linux/miz-test.efi", "unsigned_sha256": "{s}",
        \\      "signed_sha256": "{s}", "finalized_sha256": "{s}",
        \\      "signed_bytes": 4096, "signing_operation_id": "{s}",
        \\      "signing_certificate_sha256": "{s}"}},
        \\    {{"path": "{s}", "unsigned_sha256": "{s}",
        \\      "signed_sha256": "{s}", "finalized_sha256": "{s}",
        \\      "signed_bytes": 4096, "signing_operation_id": "{s}",
        \\      "signing_certificate_sha256": "{s}"}}]}}
    , .{
        options.architecture,
        options.flavor,
        options.signer_mode,
        &fingerprint,
        encoded,
        options.endpoint,
        test_signing_leaf,
        "2" ** 64,
        options.named_signed,
        options.named_signed,
        test_operation_id,
        test_signing_leaf,
        fallback,
        "2" ** 64,
        options.fallback_signed,
        options.fallback_signed,
        options.fallback_operation,
        test_signing_leaf,
    });
}

test "signing provenance binds the signer, the leaf, and the fallback UKI" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const text = try signingDocument(allocator, .{});
    var document = try parse(text);
    defer document.deinit();
    const binding = try bindSigningProvenance(
        allocator,
        &document.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    );
    try std.testing.expectEqualStrings("3" ** 64, binding.fallback_uki_sha256);
    try std.testing.expectEqualStrings(test_signing_leaf, binding.signing_certificate_sha256);
    try std.testing.expectEqualStrings("cataggar", binding.provider_account);
    try std.testing.expectEqualStrings(
        &release.digest.hexBytes(test_certificate),
        binding.certificate_sha256,
    );

    const value = try binding.toValue(allocator);
    const encoded = try json_document.canonicalAlloc(allocator, value, .compact);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"provenance_path\":\"uki-signing-full-x86_64.json\"",
    ) != null);
}

test "signing provenance rejects a fallback that is not a named signed UKI" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const detached = try signingDocument(allocator, .{ .fallback_signed = "5" ** 64 });
    var document = try parse(detached);
    defer document.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &document.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "fallback UKI is not byte-identical to a named signed UKI",
        diagnostic.message(),
    );

    const reoperated = try signingDocument(allocator, .{
        .fallback_operation = "00000000-0000-4000-8000-000000000002",
    });
    var second = try parse(reoperated);
    defer second.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &second.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "fallback UKI does not retain its named UKI signing operation",
        diagnostic.message(),
    );
}

test "signing provenance rejects a self-signed or mismatched signer" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const internal = try signingDocument(allocator, .{ .signer_mode = "built-in" });
    var document = try parse(internal);
    defer document.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &document.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "release UKIs were not signed by the external provider",
        diagnostic.message(),
    );

    const foreign = try signingDocument(allocator, .{
        .endpoint = "https://attacker.example.com",
    });
    var second = try parse(foreign);
    defer second.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &second.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid Artifact Signing provider identity",
        diagnostic.message(),
    );

    // An architecture the document does not claim.
    const mismatched = try signingDocument(allocator, .{ .architecture = "aarch64" });
    var third = try parse(mismatched);
    defer third.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &third.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "UKI signing provenance architecture/flavor mismatch",
        diagnostic.message(),
    );
}

test "signing provenance rejects an unsigned or unbound UKI record" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    // The signed digest equals the unsigned digest: nothing was signed.
    const unchanged = try signingDocument(allocator, .{
        .named_signed = "2" ** 64,
        .fallback_signed = "2" ** 64,
    });
    var document = try parse(unchanged);
    defer document.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &document.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "EFI/Linux/miz-test.efi: invalid signed/finalized UKI digest binding",
        diagnostic.message(),
    );

    var lonely = try parse(
        \\{"schema": 1, "type": "miz-uki-signing", "architecture": "x86_64",
        \\ "flavor": "full", "signer_mode": "external-command",
        \\ "certificate_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "certificate_der_base64": "", "certificate_details": "x",
        \\ "signature_verification": "success", "files": []}
    );
    defer lonely.deinit();
    try std.testing.expectError(error.InvalidSigningProvenance, bindSigningProvenance(
        allocator,
        &lonely.value.object,
        lookup("x86_64-full").?,
        "uki-signing-full-x86_64.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "canonical DER UKI signing certificate fingerprint mismatch",
        diagnostic.message(),
    );
}

test "the provenance digest is taken over compact sorted JSON" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const records = [_]ProvenanceRecord{
        .{ .path = "inputs.txt", .bytes = 12, .sha256 = "a" ** 64 },
        .{ .path = "nested/build.log", .bytes = 3, .sha256 = "b" ** 64 },
    };
    const value = try provenanceRecordsValue(allocator, &records);
    const encoded = try json_document.canonicalAlloc(allocator, value, .compact);
    try std.testing.expectEqualStrings(
        "[{\"bytes\":12,\"path\":\"inputs.txt\",\"sha256\":\"" ++ "a" ** 64 ++ "\"}," ++
            "{\"bytes\":3,\"path\":\"nested/build.log\",\"sha256\":\"" ++ "b" ** 64 ++ "\"}]",
        encoded,
    );
    try std.testing.expectEqualStrings(
        &release.digest.hexBytes(encoded),
        &try provenanceDigest(allocator, value),
    );
}

test "JSON equality is deep and variant-exact" {
    var left = try parse(
        \\{"a": [1, {"b": null}], "c": "x"}
    );
    defer left.deinit();
    var right = try parse(
        \\{"c": "x", "a": [1, {"b": null}]}
    );
    defer right.deinit();
    try std.testing.expect(jsonEql(left.value, right.value));

    var extra = try parse(
        \\{"c": "x", "a": [1, {"b": null}], "d": 1}
    );
    defer extra.deinit();
    try std.testing.expect(!jsonEql(left.value, extra.value));

    var floating = try parse(
        \\{"a": [1.0, {"b": null}], "c": "x"}
    );
    defer floating.deinit();
    try std.testing.expect(!jsonEql(left.value, floating.value));
}

test "Python repr is reproduced for the shapes these documents hold" {
    var parsed = try parse(
        \\{"miz-owner": "azurelinux4-release", "miz-run-id": "12", "n": null,
        \\ "ok": true, "count": 3, "list": ["a", {"b": 1}]}
    );
    defer parsed.deinit();
    const text = try pythonReprAlloc(std.testing.allocator, parsed.value);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "{'miz-owner': 'azurelinux4-release', 'miz-run-id': '12', 'n': None, " ++
            "'ok': True, 'count': 3, 'list': ['a', {'b': 1}]}",
        text,
    );

    var quoted = try parse(
        \\{"a": "it's\\ttabbed"}
    );
    defer quoted.deinit();
    const escaped = try pythonReprAlloc(std.testing.allocator, quoted.value);
    defer std.testing.allocator.free(escaped);
    try std.testing.expectEqualStrings("{'a': 'it\\'s\\\\ttabbed'}", escaped);
}
