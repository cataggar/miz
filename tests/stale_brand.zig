//! Guards the tracked tree against the brands this project renamed away from,
//! replacing `tests/stale_brand_test.py`.
//!
//! The guard enumerates git's own idea of what is tracked, rejects the legacy
//! brands in both path names and file bytes case-insensitively, and looks
//! inside every PEM certificate a `.pem` file holds -- where a name survives
//! the rename in DER metadata that no text search of the file would ever see,
//! spelled in any of the encodings X.509 string types allow.
//!
//! Every failure mode is a violation rather than a silent pass: a path that is
//! not text, a file that cannot be read, a certificate that will not decode,
//! and a `git ls-files` that will not run all fail the guard, because a check
//! that cannot be performed is not a check that passed.
//!
//! The checks are pure functions over `(path, bytes)` so they can be exercised
//! against constructed inputs. The live tracked tree is one caller of them,
//! not the only way to reach them.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The brands this repository moved away from. Spelled in halves so the
/// guard's own tracked bytes never carry what it rejects.
const legacy_brands = [_][]const u8{ "v" ++ "miz", "z" ++ "vmi" };

/// The one tracked file whose subject is the rename itself, and which must
/// therefore name what was renamed.
const allowed_content_paths = [_][]const u8{"doc/migration.md"};

/// A `.pem` fixture that deliberately holds no certificate: the consumer test
/// it belongs to only needs a file at that path, so its undecodable body is
/// the point rather than a defect.
const allowed_non_certificate_pem_paths = [_][]const u8{
    "tests/build_api_consumer/fixtures/registry-ca.pem",
};

const pem_begin = "-----BEGIN CERTIFICATE-----";
const pem_end = "-----END CERTIFICATE-----";

/// Tracked files are read whole. The largest tracked file is under a
/// megabyte, so this limit only ever catches something new and enormous --
/// which is reported rather than skipped.
const max_tracked_file_bytes = 64 * 1024 * 1024;

/// `git ls-files -z` over this repository emits a few kilobytes; the limit is
/// generous enough that reaching it means the enumeration itself is wrong.
const max_git_output_bytes = 16 * 1024 * 1024;

/// How many bytes of `git`'s stderr a failure diagnostic repeats.
const max_reported_stderr_bytes = 4 * 1024;

/// The encodings an X.509 directory string can carry. `PrintableString`,
/// `UTF8String` and `IA5String` all spell ASCII as ASCII; `BMPString` is
/// UTF-16 and `UniversalString` is UTF-32, either endianness of which hides a
/// name from a plain byte search.
const Encoding = enum {
    ascii,
    utf16_be,
    utf16_le,
    utf32_be,
    utf32_le,

    fn codeUnitBytes(self: Encoding) usize {
        return switch (self) {
            .ascii => 1,
            .utf16_be, .utf16_le => 2,
            .utf32_be, .utf32_le => 4,
        };
    }

    /// Where the ASCII byte of a code unit sits: last for big-endian, first
    /// for little-endian.
    fn codeUnitOffset(self: Encoding) usize {
        return switch (self) {
            .ascii, .utf16_le, .utf32_le => 0,
            .utf16_be => 1,
            .utf32_be => 3,
        };
    }
};

/// Widens an ASCII brand into one code unit per character.
fn encodeBrand(comptime brand: []const u8, comptime encoding: Encoding) []const u8 {
    const unit = encoding.codeUnitBytes();
    var encoded: [brand.len * unit]u8 = @splat(0);
    for (brand, 0..) |byte, index| {
        encoded[index * unit + encoding.codeUnitOffset()] = byte;
    }
    const frozen = encoded;
    return &frozen;
}

/// Every legacy brand in every encoding certificate metadata can hold.
const encoded_legacy_brands = blk: {
    const encodings = std.enums.values(Encoding);
    var encoded: [legacy_brands.len * encodings.len][]const u8 = undefined;
    var next: usize = 0;
    for (legacy_brands) |brand| {
        for (encodings) |encoding| {
            encoded[next] = encodeBrand(brand, encoding);
            next += 1;
        }
    }
    const frozen = encoded;
    break :blk frozen;
};

/// The diagnostics a scan produced. Everything the guard rejects lands here,
/// so a run that could not complete its checks fails exactly like one that
/// found branding.
pub const Report = struct {
    allocator: Allocator,
    violations: std.ArrayList([]u8) = .empty,

    pub fn init(allocator: Allocator) Report {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Report) void {
        for (self.violations.items) |violation| self.allocator.free(violation);
        self.violations.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isClean(self: *const Report) bool {
        return self.violations.items.len == 0;
    }

    fn add(self: *Report, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        const text = try std.fmt.allocPrint(self.allocator, fmt, args);
        errdefer self.allocator.free(text);
        try self.violations.append(self.allocator, text);
    }

    /// One violation per line, each named by the path it came from. Caller
    /// owns the returned text.
    pub fn render(self: *const Report, allocator: Allocator) Allocator.Error![]u8 {
        var text: std.ArrayList(u8) = .empty;
        errdefer text.deinit(allocator);
        for (self.violations.items) |violation| {
            try text.append(allocator, '\n');
            try text.appendSlice(allocator, violation);
        }
        return text.toOwnedSlice(allocator);
    }
};

/// Runs every check the guard makes about one tracked file.
pub fn checkTrackedFile(
    report: *Report,
    raw_path: []const u8,
    contents: []const u8,
) Allocator.Error!void {
    try checkTrackedPath(report, raw_path);
    try checkTrackedContents(report, raw_path, contents);
}

/// Rejects a tracked path that carries a legacy brand, or that is not text at
/// all -- a path no diagnostic can quote faithfully is a path no reviewer can
/// act on, so it is reported rather than decoded lossily and forgotten.
pub fn checkTrackedPath(report: *Report, raw_path: []const u8) Allocator.Error!void {
    if (!std.unicode.utf8ValidateSlice(raw_path)) {
        try addPathViolation(
            report,
            raw_path,
            "tracked path is not valid UTF-8",
            .{},
        );
    }
    for (legacy_brands) |brand| {
        if (indexOfLowercase(raw_path, brand) != null) {
            try addPathViolation(
                report,
                raw_path,
                "legacy brand in tracked path",
                .{},
            );
        }
    }
}

/// Rejects legacy branding in a tracked file's bytes, and in the metadata of
/// every certificate a `.pem` file holds.
pub fn checkTrackedContents(
    report: *Report,
    raw_path: []const u8,
    contents: []const u8,
) Allocator.Error!void {
    if (isListed(raw_path, &allowed_content_paths)) return;

    for (legacy_brands) |brand| {
        if (indexOfLowercase(contents, brand)) |offset| {
            const line = std.mem.count(u8, contents[0..offset], "\n") + 1;
            const display = try displayPath(report.allocator, raw_path);
            defer report.allocator.free(display);
            try report.add(
                "{s}:{d}: legacy brand in tracked content",
                .{ display, line },
            );
        }
    }

    if (!std.ascii.eqlIgnoreCase(std.fs.path.extension(raw_path), ".pem")) return;
    try checkPemCertificates(report, raw_path, contents);
}

/// Walks every `BEGIN`/`END` certificate block in a PEM file, in order, and
/// scans the DER behind each one.
fn checkPemCertificates(
    report: *Report,
    raw_path: []const u8,
    contents: []const u8,
) Allocator.Error!void {
    const allocator = report.allocator;
    const exempt = isListed(raw_path, &allowed_non_certificate_pem_paths);

    var search: usize = 0;
    var certificate_index: usize = 0;
    while (std.mem.indexOfPos(u8, contents, search, pem_begin)) |begin| {
        certificate_index += 1;
        const body_start = begin + pem_begin.len;
        const body_end = std.mem.indexOfPos(u8, contents, body_start, pem_end) orelse {
            // An unterminated block is text no certificate parser accepts, so
            // its bytes were never scanned. Saying so beats passing quietly.
            if (exempt) return;
            try addPathViolation(
                report,
                raw_path,
                "certificate {d} is missing its `{s}` line",
                .{ certificate_index, pem_end },
            );
            return;
        };
        search = body_end + pem_end.len;

        const der = decodePemBody(allocator, contents[body_start..body_end]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (exempt) continue;
                try addPathViolation(
                    report,
                    raw_path,
                    "certificate {d} cannot be decoded: {t}",
                    .{ certificate_index, err },
                );
                continue;
            },
        };
        defer allocator.free(der);

        for (encoded_legacy_brands) |encoded_brand| {
            if (indexOfLowercase(der, encoded_brand) != null) {
                try addPathViolation(
                    report,
                    raw_path,
                    "certificate {d} contains legacy branding in DER metadata",
                    .{certificate_index},
                );
                break;
            }
        }
    }
}

const PemDecodeError = error{
    InvalidCharacter,
    InvalidPadding,
    NoSpaceLeft,
    OutOfMemory,
};

/// Decodes the base64 body of a PEM block. Line breaks and other ASCII
/// whitespace are structure rather than data; anything else outside the
/// alphabet makes the block undecodable, which the caller reports.
fn decodePemBody(allocator: Allocator, body: []const u8) PemDecodeError![]u8 {
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(allocator);
    try compact.ensureTotalCapacity(allocator, body.len);
    for (body) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        compact.appendAssumeCapacity(byte);
    }

    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(compact.items);
    const der = try allocator.alloc(u8, size);
    errdefer allocator.free(der);
    try decoder.decode(der, compact.items);
    return der;
}

/// Scans the tracked tree rooted at `root_path`. The caller owns the report.
pub fn scanTrackedTree(allocator: Allocator, io: Io, root_path: []const u8) Allocator.Error!Report {
    var report = Report.init(allocator);
    errdefer report.deinit();

    const listing = std.process.run(allocator, io, .{
        .argv = &.{ "git", "-C", root_path, "ls-files", "-z" },
        .stdout_limit = .limited(max_git_output_bytes),
        .stderr_limit = .limited(max_git_output_bytes),
    }) catch |err| {
        try report.add(
            "{s}: `git ls-files -z` could not be run: {t}",
            .{ root_path, err },
        );
        return report;
    };
    defer allocator.free(listing.stdout);
    defer allocator.free(listing.stderr);

    switch (listing.term) {
        .exited => |code| if (code != 0) {
            try report.add(
                "{s}: `git ls-files -z` exited with code {d}: {s}",
                .{ root_path, code, reportableStderr(listing.stderr) },
            );
            return report;
        },
        else => {
            try report.add(
                "{s}: `git ls-files -z` terminated abnormally: {s}",
                .{ root_path, reportableStderr(listing.stderr) },
            );
            return report;
        },
    }

    // `-z` is what makes the enumeration total: NUL is the one byte a path
    // cannot contain, so every tracked name arrives whole however it is
    // spelled.
    var entries = std.mem.splitScalar(u8, listing.stdout, 0);
    while (entries.next()) |raw_path| {
        if (raw_path.len == 0) continue;
        try checkTrackedPath(&report, raw_path);
        if (isListed(raw_path, &allowed_content_paths)) continue;

        const full_path = try std.fs.path.join(allocator, &.{ root_path, raw_path });
        defer allocator.free(full_path);

        const contents = Io.Dir.cwd().readFileAlloc(
            io,
            full_path,
            allocator,
            .limited(max_tracked_file_bytes),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => {
                try addPathViolation(
                    &report,
                    raw_path,
                    "tracked file is larger than the {d} byte scan limit",
                    .{max_tracked_file_bytes},
                );
                continue;
            },
            else => {
                try addPathViolation(
                    &report,
                    raw_path,
                    "tracked file could not be read: {t}",
                    .{err},
                );
                continue;
            },
        };
        defer allocator.free(contents);

        try checkTrackedContents(&report, raw_path, contents);
    }

    return report;
}

fn reportableStderr(stderr: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, stderr, " \t\r\n");
    if (trimmed.len <= max_reported_stderr_bytes) return trimmed;
    return trimmed[0..max_reported_stderr_bytes];
}

fn isListed(raw_path: []const u8, listed: []const []const u8) bool {
    for (listed) |candidate| {
        if (std.mem.eql(u8, raw_path, candidate)) return true;
    }
    return false;
}

/// Prefixes a diagnostic with the path it belongs to, quoting bytes that are
/// not printable text as escapes so the message stays readable and the path
/// stays recognizable.
fn addPathViolation(
    report: *Report,
    raw_path: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) Allocator.Error!void {
    const display = try displayPath(report.allocator, raw_path);
    defer report.allocator.free(display);
    try report.add("{s}: " ++ fmt, .{display} ++ args);
}

fn displayPath(allocator: Allocator, raw_path: []const u8) Allocator.Error![]u8 {
    // A path that is valid UTF-8 is quoted as it is, so a legitimately
    // non-ASCII name still reads as itself; anything else is escaped byte by
    // byte, since a diagnostic that emits raw bytes names nothing.
    const is_text = std.unicode.utf8ValidateSlice(raw_path);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    for (raw_path) |byte| {
        if (std.ascii.isPrint(byte) or (is_text and byte >= 0x80)) {
            try text.append(allocator, byte);
        } else {
            try text.print(allocator, "\\x{x:0>2}", .{byte});
        }
    }
    return text.toOwnedSlice(allocator);
}

/// Finds an already-lowercased needle in a haystack of any case. Both brands
/// and their encoded forms are lowercase ASCII, so folding the haystack alone
/// is the whole of the case-insensitive comparison, and the NUL padding of a
/// UTF-16 or UTF-32 needle compares unchanged.
fn indexOfLowercase(haystack: []const u8, lowercase_needle: []const u8) ?usize {
    if (lowercase_needle.len == 0) return null;
    if (haystack.len < lowercase_needle.len) return null;
    const last_start = haystack.len - lowercase_needle.len;
    var start: usize = 0;
    while (start <= last_start) : (start += 1) {
        if (std.ascii.toLower(haystack[start]) != lowercase_needle[0]) continue;
        const window = haystack[start..][0..lowercase_needle.len];
        if (std.ascii.eqlIgnoreCase(window, lowercase_needle)) return start;
    }
    return null;
}

// ---- tests ----

const testing = std.testing;

/// Builds a PEM certificate block around arbitrary DER bytes. Caller owns the
/// result.
fn buildPemCertificate(allocator: Allocator, der: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der.len));
    defer allocator.free(encoded);
    const body = encoder.encode(encoded, der);
    return std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ pem_begin, body, pem_end });
}

fn expectSingleViolation(report: *const Report, expected: []const u8) !void {
    if (report.violations.items.len != 1) {
        const rendered = try report.render(testing.allocator);
        defer testing.allocator.free(rendered);
        std.debug.print("expected one violation, got:{s}\n", .{rendered});
        return error.UnexpectedViolationCount;
    }
    try testing.expectEqualStrings(expected, report.violations.items[0]);
}

test "a clean tracked file yields no violations" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    try checkTrackedFile(&report, "packages/miz/src/root.zig", "const miz = @import(\"miz\");\n");
    try testing.expect(report.isClean());
}

test "a legacy brand in a tracked path is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    try checkTrackedPath(&report, "packages/" ++ legacy_brands[0] ++ "/src/root.zig");
    try expectSingleViolation(
        &report,
        "packages/" ++ legacy_brands[0] ++ "/src/root.zig: legacy brand in tracked path",
    );
}

test "a legacy brand in a tracked path is matched case-insensitively" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    var storage: [legacy_brands[1].len]u8 = undefined;
    const upper = std.ascii.upperString(&storage, legacy_brands[1]);
    const path = try std.fmt.allocPrint(testing.allocator, "doc/{s}.md", .{upper});
    defer testing.allocator.free(path);
    const expected = try std.fmt.allocPrint(
        testing.allocator,
        "{s}: legacy brand in tracked path",
        .{path},
    );
    defer testing.allocator.free(expected);
    try checkTrackedPath(&report, path);
    try expectSingleViolation(&report, expected);
}

test "both legacy brands in one path are reported separately" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    try checkTrackedPath(&report, legacy_brands[0] ++ "/" ++ legacy_brands[1] ++ ".md");
    try testing.expectEqual(@as(usize, 2), report.violations.items.len);
}

test "a tracked path that is not valid UTF-8 is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    try checkTrackedPath(&report, "doc/\xffbroken.md");
    try expectSingleViolation(&report, "doc/\\xffbroken.md: tracked path is not valid UTF-8");
}

test "legacy branding in tracked content reports its line" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const contents = "first\nsecond\nthird " ++ legacy_brands[0] ++ "\nfourth\n";
    try checkTrackedContents(&report, "doc/readme.md", contents);
    try expectSingleViolation(&report, "doc/readme.md:3: legacy brand in tracked content");
}

test "legacy branding in tracked content is matched case-insensitively" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    var storage: [legacy_brands[0].len]u8 = undefined;
    const upper = std.ascii.upperString(&storage, legacy_brands[0]);
    const contents = try std.fmt.allocPrint(testing.allocator, "release {s}\n", .{upper});
    defer testing.allocator.free(contents);
    try checkTrackedContents(&report, "doc/readme.md", contents);
    try expectSingleViolation(&report, "doc/readme.md:1: legacy brand in tracked content");
}

test "legacy branding in binary content is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const contents = "\x00\x01\x02\n\xff\xfe" ++ legacy_brands[1] ++ "\x00";
    try checkTrackedContents(&report, "tests/fixtures/blob.bin", contents);
    try expectSingleViolation(&report, "tests/fixtures/blob.bin:2: legacy brand in tracked content");
}

test "the migration document is exempt from the content scan" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const contents = "The rename from " ++ legacy_brands[0] ++ " to miz.\n";
    try checkTrackedContents(&report, allowed_content_paths[0], contents);
    try testing.expect(report.isClean());
}

test "the migration document is not exempt from the path scan" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    try checkTrackedPath(&report, allowed_content_paths[0]);
    try testing.expect(report.isClean());
    try checkTrackedPath(&report, "doc/" ++ legacy_brands[0] ++ "-migration.md");
    try testing.expectEqual(@as(usize, 1), report.violations.items.len);
}

test "certificate metadata is scanned in every encoding" {
    inline for (comptime std.enums.values(Encoding)) |encoding| {
        inline for (legacy_brands, 0..) |brand, brand_index| {
            var report = Report.init(testing.allocator);
            defer report.deinit();

            const der = "\x30\x82\x01\x0a" ++ comptime encodeBrand(brand, encoding) ++ "\x00\x01";
            const pem = try buildPemCertificate(testing.allocator, der);
            defer testing.allocator.free(pem);

            try checkTrackedContents(&report, "tests/fixtures/branded.pem", pem);
            expectSingleViolation(
                &report,
                "tests/fixtures/branded.pem: certificate 1 contains legacy branding in DER metadata",
            ) catch |err| {
                std.debug.print(
                    "encoding {t} brand {d} was not detected\n",
                    .{ encoding, brand_index },
                );
                return err;
            };
        }
    }
}

test "certificate metadata is scanned case-insensitively" {
    var report = Report.init(testing.allocator);
    defer report.deinit();

    var storage: [legacy_brands[0].len]u8 = undefined;
    const upper = std.ascii.upperString(&storage, legacy_brands[0]);
    const der = try std.fmt.allocPrint(testing.allocator, "\x30\x82{s}\x00", .{upper});
    defer testing.allocator.free(der);

    const pem = try buildPemCertificate(testing.allocator, der);
    defer testing.allocator.free(pem);

    try checkTrackedContents(&report, "tests/fixtures/branded.pem", pem);
    try expectSingleViolation(
        &report,
        "tests/fixtures/branded.pem: certificate 1 contains legacy branding in DER metadata",
    );
}

test "a certificate free of legacy branding passes" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = try buildPemCertificate(testing.allocator, "\x30\x82\x01\x0amiz\x00");
    defer testing.allocator.free(pem);
    try checkTrackedContents(&report, "tests/fixtures/clean.pem", pem);
    try testing.expect(report.isClean());
}

test "only .pem files are parsed as certificates" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = try buildPemCertificate(
        testing.allocator,
        "\x30\x82" ++ comptime encodeBrand(legacy_brands[0], .utf16_be),
    );
    defer testing.allocator.free(pem);
    try checkTrackedContents(&report, "tests/fixtures/certificate.txt", pem);
    try testing.expect(report.isClean());
}

test "a .PEM suffix is recognized whatever its case" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = try buildPemCertificate(
        testing.allocator,
        "\x30\x82" ++ comptime encodeBrand(legacy_brands[0], .utf32_le),
    );
    defer testing.allocator.free(pem);
    try checkTrackedContents(&report, "tests/fixtures/Branded.PEM", pem);
    try expectSingleViolation(
        &report,
        "tests/fixtures/Branded.PEM: certificate 1 contains legacy branding in DER metadata",
    );
}

test "every certificate block in a file is parsed" {
    var report = Report.init(testing.allocator);
    defer report.deinit();

    const clean = try buildPemCertificate(testing.allocator, "\x30\x82miz");
    defer testing.allocator.free(clean);
    const branded = try buildPemCertificate(
        testing.allocator,
        "\x30\x82" ++ comptime encodeBrand(legacy_brands[1], .utf16_le),
    );
    defer testing.allocator.free(branded);

    const bundle = try std.fmt.allocPrint(
        testing.allocator,
        "# leading comment\n{s}\n{s}",
        .{ clean, branded },
    );
    defer testing.allocator.free(bundle);

    try checkTrackedContents(&report, "tests/fixtures/bundle.pem", bundle);
    try expectSingleViolation(
        &report,
        "tests/fixtures/bundle.pem: certificate 2 contains legacy branding in DER metadata",
    );
}

test "a certificate whose base64 cannot be decoded is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = pem_begin ++ "\nnot-a-real-certificate\n" ++ pem_end ++ "\n";
    try checkTrackedContents(&report, "tests/fixtures/broken.pem", pem);
    try expectSingleViolation(
        &report,
        "tests/fixtures/broken.pem: certificate 1 cannot be decoded: InvalidPadding",
    );
}

test "a certificate holding a character outside the base64 alphabet is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = pem_begin ++ "\nQU-D\n" ++ pem_end ++ "\n";
    try checkTrackedContents(&report, "tests/fixtures/broken.pem", pem);
    try expectSingleViolation(
        &report,
        "tests/fixtures/broken.pem: certificate 1 cannot be decoded: InvalidCharacter",
    );
}

test "a wrapped, CRLF-terminated certificate body still decodes" {
    var report = Report.init(testing.allocator);
    defer report.deinit();

    const der = "\x30\x82" ++ comptime encodeBrand(legacy_brands[0], .utf16_be);
    const encoder = std.base64.standard.Encoder;
    const encoded = try testing.allocator.alloc(u8, encoder.calcSize(der.len));
    defer testing.allocator.free(encoded);
    const body = encoder.encode(encoded, der);

    var pem: std.ArrayList(u8) = .empty;
    defer pem.deinit(testing.allocator);
    try pem.appendSlice(testing.allocator, pem_begin ++ "\r\n");
    var offset: usize = 0;
    while (offset < body.len) : (offset += 4) {
        try pem.appendSlice(testing.allocator, body[offset..@min(offset + 4, body.len)]);
        try pem.appendSlice(testing.allocator, "\r\n");
    }
    try pem.appendSlice(testing.allocator, pem_end ++ "\r\n");

    try checkTrackedContents(&report, "tests/fixtures/wrapped.pem", pem.items);
    try expectSingleViolation(
        &report,
        "tests/fixtures/wrapped.pem: certificate 1 contains legacy branding in DER metadata",
    );
}

test "an undecodable certificate does not stop the ones after it" {
    var report = Report.init(testing.allocator);
    defer report.deinit();

    const branded = try buildPemCertificate(
        testing.allocator,
        "\x30\x82" ++ comptime encodeBrand(legacy_brands[0], .utf32_be),
    );
    defer testing.allocator.free(branded);
    const bundle = try std.fmt.allocPrint(
        testing.allocator,
        "{s}\n{s}",
        .{ pem_begin ++ "\nnot-a-real-certificate\n" ++ pem_end, branded },
    );
    defer testing.allocator.free(bundle);

    try checkTrackedContents(&report, "tests/fixtures/bundle.pem", bundle);
    try testing.expectEqual(@as(usize, 2), report.violations.items.len);
    try testing.expectEqualStrings(
        "tests/fixtures/bundle.pem: certificate 1 cannot be decoded: InvalidPadding",
        report.violations.items[0],
    );
    try testing.expectEqualStrings(
        "tests/fixtures/bundle.pem: certificate 2 contains legacy branding in DER metadata",
        report.violations.items[1],
    );
}

test "the non-certificate PEM fixture is exempt from decoding" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = pem_begin ++ "\nnot-a-real-certificate\n" ++ pem_end ++ "\n";
    try checkTrackedContents(&report, allowed_non_certificate_pem_paths[0], pem);
    try testing.expect(report.isClean());
}

test "the non-certificate PEM exemption does not excuse decodable branding" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = try buildPemCertificate(
        testing.allocator,
        "\x30\x82" ++ comptime encodeBrand(legacy_brands[0], .ascii),
    );
    defer testing.allocator.free(pem);
    try checkTrackedContents(&report, allowed_non_certificate_pem_paths[0], pem);
    try expectSingleViolation(
        &report,
        allowed_non_certificate_pem_paths[0] ++
            ": certificate 1 contains legacy branding in DER metadata",
    );
}

test "an unterminated certificate block is reported" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = pem_begin ++ "\nQUJD\n";
    try checkTrackedContents(&report, "tests/fixtures/truncated.pem", pem);
    try expectSingleViolation(
        &report,
        "tests/fixtures/truncated.pem: certificate 1 is missing its `" ++ pem_end ++ "` line",
    );
}

test "a PEM file holding no certificate block is not a violation" {
    var report = Report.init(testing.allocator);
    defer report.deinit();
    const pem = "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n";
    try checkTrackedContents(&report, "tests/fixtures/signing-key.pem", pem);
    try testing.expect(report.isClean());
}

test "an enumeration that cannot run fails the scan" {
    const allocator = testing.allocator;
    var report = try scanTrackedTree(
        allocator,
        testing.io,
        "tests/fixtures/definitely-not-a-repository",
    );
    defer report.deinit();
    try testing.expect(!report.isClean());
    try testing.expect(
        std.mem.indexOf(u8, report.violations.items[0], "git ls-files -z") != null,
    );
}

test "tracked tree uses only the canonical brand" {
    const allocator = testing.allocator;
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);

    var report = try scanTrackedTree(allocator, testing.io, root);
    defer report.deinit();
    if (report.isClean()) return;

    const rendered = try report.render(allocator);
    defer allocator.free(rendered);
    std.debug.print("legacy branding in the tracked tree:{s}\n", .{rendered});
    return error.LegacyBrandingFound;
}

/// The tree to scan. `build.zig` names the build root outright, so the guard
/// does not depend on which directory the test binary was started in. Caller
/// owns the returned path.
fn repositoryRootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(allocator, "MIZ_STALE_BRAND_ROOT") catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}
