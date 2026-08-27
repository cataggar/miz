//! Candidate validation and result documents for the FreeBSD 15.1 release.
//!
//! Native port of the candidate half of `scripts/freebsd15_release.py`: the
//! recorded package manifest parser, the trusted `qemu-img` document reader,
//! the `candidate` and `azure-result` writers, and `validate_candidate`, which
//! is the one function every later stage re-runs. The release helper must be
//! able to reject a candidate without trusting the builder that produced it,
//! so every field the builder recorded is re-derived from the artifact beside
//! it rather than believed.

const std = @import("std");
const profiles = @import("profiles.zig");
const document = @import("document.zig");
const support = @import("release");
const azure_vhd = support.azure_vhd_layout;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const contract = support.contract;
const digest = support.digest;
const file_support = support.file;
const json_document = support.json_document;

pub const Context = document.Context;
pub const Error = document.Error;

/// Release metadata documents are kilobytes; a full image's recorded package
/// manifest is the largest of them and stays well inside this bound.
pub const max_document_bytes: u64 = 8 * 1024 * 1024;
/// Published assets are a few gigabytes compressed. The bound only ever
/// catches something that is not a release artifact at all.
pub const max_asset_bytes: u64 = 64 * 1024 * 1024 * 1024;

pub const candidate_type = "miz-freebsd15-candidate";
pub const azure_result_type = "miz-freebsd15-azure-acceptance";
pub const release_type = "miz-freebsd15-release";

// ---- Filesystem helpers ---------------------------------------------------

/// `Path.resolve(strict=True)`: the absolute path, and proof the file exists.
pub fn realPath(context: *Context, path: []const u8) Error![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = Dir.cwd().realPathFile(context.io, path, &buffer) catch |err|
        return context.fail("cannot resolve {s}: {t}", .{ path, err });
    return context.arena.dupe(u8, buffer[0..length]);
}

/// Streaming SHA-256 over a file that must exist and be regular.
pub fn hashFile(context: *Context, path: []const u8) Error!digest.Hex {
    const result = digest.hashFile(context.io, path, max_asset_bytes) catch |err|
        return context.fail("cannot read {s}: {t}", .{ path, err });
    return result.hex;
}

pub fn isRegularFile(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .file;
}

pub fn regularFileSize(context: *Context, path: []const u8) Error!u64 {
    return file_support.regularFileSize(context.io, path) catch |err|
        return context.fail("cannot read {s}: {t}", .{ path, err });
}

/// The directory a path lives in, spelled the way `Path.parent` would be
/// compared: an empty dirname means the working directory.
pub fn parentOf(path: []const u8) []const u8 {
    return std.fs.path.dirname(path) orelse ".";
}

pub fn joinPath(context: *Context, parts: []const []const u8) Error![]const u8 {
    return std.fs.path.join(context.arena, parts);
}

/// Reads a JSON object into the context arena, so the parsed values outlive
/// the call without a second ownership rule.
pub fn readObject(context: *Context, path: []const u8) Error!Value {
    const parsed = json_document.readObject(
        context.arena,
        context.io,
        path,
        max_document_bytes,
        &context.diagnostic,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Invalid,
    };
    return parsed.parsed.value;
}

// ---- Recorded package manifests -------------------------------------------

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    installed_bytes: i64,
};

/// `parse_package_manifest`: a `<asset>.packages.txt` the builder recorded from
/// the guest, one `name version installed_bytes` record per line.
pub fn parsePackageManifest(
    context: *Context,
    path: []const u8,
) Error![]const Package {
    const bytes = file_support.readBounded(
        context.arena,
        context.io,
        path,
        max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };

    var packages: std.ArrayList(Package) = .empty;
    var number: usize = 0;
    var lines = splitPythonLines(bytes);
    while (lines.next()) |line| {
        number += 1;
        const record = parsePackageRecord(line) orelse return context.fail(
            "{s}:{d}: malformed package record",
            .{ path, number },
        );
        for (packages.items) |seen| {
            if (std.mem.eql(u8, seen.name, record.name)) return context.fail(
                "{s}:{d}: duplicate package {s}",
                .{ path, number, record.name },
            );
        }
        try packages.append(context.arena, record);
    }
    if (packages.items.len == 0) return context.fail(
        "{s}: no packages recorded",
        .{path},
    );
    return packages.items;
}

/// `str.splitlines()` over the line endings a recorded manifest can carry: a
/// trailing newline ends the last record rather than starting an empty one.
pub fn splitPythonLines(bytes: []const u8) LineIterator {
    return .{ .rest = bytes };
}

pub const LineIterator = struct {
    rest: []const u8,
    done: bool = false,

    pub fn next(self: *LineIterator) ?[]const u8 {
        if (self.done or self.rest.len == 0) {
            self.done = true;
            return null;
        }
        const break_index = std.mem.indexOfScalar(u8, self.rest, '\n') orelse {
            const line = self.rest;
            self.rest = self.rest[self.rest.len..];
            self.done = true;
            return std.mem.trimEnd(u8, line, "\r");
        };
        const line = self.rest[0..break_index];
        self.rest = self.rest[break_index + 1 ..];
        return std.mem.trimEnd(u8, line, "\r");
    }
};

/// `PACKAGE_RECORD_RE`: `^(\S+) (\S+) (\d+)$`.
fn parsePackageRecord(line: []const u8) ?Package {
    const first = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const rest = line[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const name = line[0..first];
    const version = rest[0..second];
    const size = rest[second + 1 ..];
    if (!isNonSpace(name) or !isNonSpace(version)) return null;
    if (size.len == 0) return null;
    for (size) |character| if (!std.ascii.isDigit(character)) return null;
    const installed_bytes = std.fmt.parseInt(i64, size, 10) catch return null;
    return .{ .name = name, .version = version, .installed_bytes = installed_bytes };
}

fn isNonSpace(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |character| switch (character) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => return false,
        else => {},
    };
    return true;
}

/// `verify_package_manifest`: the reviewed contract, checked against what an
/// image actually recorded.
pub fn verifyPackageManifest(
    context: *Context,
    filesystem: []const u8,
    flavor: []const u8,
    names: []const []const u8,
) Error!void {
    const manifest = try requirePackageManifest(context, filesystem, flavor);
    for (manifest.required) |required| {
        if (!containsName(names, required)) return context.fail(
            "recorded manifest is missing {s}",
            .{required},
        );
    }

    const sorted = try context.gpa.dupe([]const u8, names);
    defer context.gpa.free(sorted);
    std.mem.sort([]const u8, sorted, {}, lessThanName);
    for (sorted) |name| {
        if (containsName(manifest.excluded, name)) return context.fail(
            "recorded manifest still carries {s}",
            .{name},
        );
        for (manifest.excluded_classes) |name_class| {
            if (profiles.hasNameClass(name, name_class)) return context.fail(
                "recorded manifest still carries {s}",
                .{name},
            );
        }
    }
}

fn lessThanName(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn containsName(names: []const []const u8, wanted: []const u8) bool {
    for (names) |name| if (std.mem.eql(u8, name, wanted)) return true;
    return false;
}

pub fn requirePackageManifest(
    context: *Context,
    filesystem: []const u8,
    flavor: []const u8,
) Error!*const profiles.PackageManifest {
    if (!profiles.hasFilesystem(filesystem)) return context.fail(
        "unsupported FreeBSD filesystem: {s}",
        .{filesystem},
    );
    return profiles.packageManifest(filesystem, flavor) orelse context.fail(
        "unsupported FreeBSD flavor: {s}",
        .{flavor},
    );
}

pub fn requireVariant(
    context: *Context,
    architecture: []const u8,
    filesystem: []const u8,
    flavor: []const u8,
) Error!*const profiles.Variant {
    return profiles.variantFor(architecture, filesystem, flavor) orelse
        context.fail("unsupported FreeBSD variant: {s}-{s}-{s}", .{
            architecture,
            filesystem,
            flavor,
        });
}

pub fn requireReleaseSet(
    context: *Context,
    name: []const u8,
) Error!*const profiles.ReleaseSet {
    return profiles.findReleaseSet(name) orelse
        context.fail("unsupported FreeBSD release set: {s}", .{name});
}

// ---- Release identity -----------------------------------------------------

pub const ReleaseIdentity = struct {
    tag: []const u8,
    title: []const u8,
};

/// `release_identity`.
pub fn releaseIdentity(
    context: *Context,
    name: []const u8,
    release_date: ?[]const u8,
) Error!ReleaseIdentity {
    const selected = try requireReleaseSet(context, name);
    if (!selected.requires_release_date) {
        if (release_date) |value| if (value.len != 0) return context.fail(
            "release date is not applicable to this release set",
            .{},
        );
        unreachable; // Every declared release set is date qualified.
    }
    const reviewed = try document.requireReleaseDate(context, release_date);
    const tag = try std.fmt.allocPrint(context.arena, "{s}{s}", .{
        selected.release_tag_prefix,
        reviewed,
    });
    if (profiles.reservedTag(tag)) |reserved| return context.fail(
        "{s} belongs to {s}",
        .{ reserved.tag, reserved.reason },
    );
    return .{
        .tag = tag,
        .title = try std.fmt.allocPrint(context.arena, "{s}{s}", .{
            selected.release_title_prefix,
            reviewed,
        }),
    };
}

/// `validate_release_tag`.
pub fn validateReleaseTag(
    context: *Context,
    name: []const u8,
    tag: ?[]const u8,
) Error!void {
    const selected = try requireReleaseSet(context, name);
    const text = tag orelse return context.fail("release tag must be a string", .{});
    std.debug.assert(selected.requires_release_date);
    if (!std.mem.startsWith(u8, text, selected.release_tag_prefix)) return context.fail(
        "{s} release tag does not match release set",
        .{name},
    );
    const identity = try releaseIdentity(
        context,
        name,
        text[selected.release_tag_prefix.len..],
    );
    if (!std.mem.eql(u8, text, identity.tag)) return context.fail(
        "{s} release tag does not match release set",
        .{name},
    );
}

// ---- Trusted qemu-img document --------------------------------------------

pub const QemuImage = struct {
    virtual_size: i64,
    allocated_size: i64,

    /// The `qemu_image` sub-document a candidate records, rebuilt so it can be
    /// compared with what a candidate claims.
    pub fn toValue(self: QemuImage, arena: Allocator) Error!Value {
        var object: std.json.ObjectMap = .empty;
        try object.put(arena, "format", .{ .string = "qcow2" });
        try object.put(arena, "virtual_size", .{ .integer = self.virtual_size });
        try object.put(arena, "allocated_size", .{ .integer = self.allocated_size });
        try object.put(arena, "compression_type", .{ .string = "zstd" });
        try object.put(arena, "has_backing_file", .{ .bool = false });
        return .{ .object = object };
    }
};

/// `load_qemu_image_info`: the trusted `qemu-img info --output=json` result the
/// build job captured, checked against the pinned profile.
pub fn loadQemuImageInfo(
    context: *Context,
    path: []const u8,
    expected_virtual_size: i64,
) Error!QemuImage {
    const value = try readObject(context, path);
    const object = value.object;

    if (!document.eqlString(object.get("format"), "qcow2")) return context.fail(
        "qemu-img validation format must be qcow2",
        .{},
    );
    const virtual_size = try document.requirePositiveInt(
        context,
        object.get("virtual-size"),
        "qemu-img virtual size",
        .{},
    );
    if (virtual_size != expected_virtual_size) return context.fail(
        "qemu-img virtual size does not match the pinned profile",
        .{},
    );
    const allocated_size = try document.requirePositiveInt(
        context,
        object.get("actual-size"),
        "qemu-img allocated size",
        .{},
    );
    if (allocated_size > virtual_size) return context.fail(
        "qemu-img allocated size exceeds virtual size",
        .{},
    );
    if (!document.isAbsentOrEmpty(object.get("backing-filename"))) return context.fail(
        "qemu-img validation reports a backing file",
        .{},
    );
    const format_specific = document.objectOf(object.get("format-specific"));
    const data = if (format_specific) |specific|
        document.objectOf(specific.get("data"))
    else
        null;
    const compression = if (data) |present| present.get("compression-type") else null;
    if (!document.eqlString(compression, "zstd")) return context.fail(
        "qemu-img validation compression type must be zstd",
        .{},
    );
    return .{ .virtual_size = virtual_size, .allocated_size = allocated_size };
}

// ---- candidate ------------------------------------------------------------

pub const CandidateArguments = struct {
    architecture: []const u8,
    filesystem: []const u8,
    flavor: []const u8,
    package_manifest: []const u8,
    asset: []const u8,
    validated_sha256: []const u8,
    virtual_size: i64,
    qemu_info: []const u8,
    source_name: []const u8,
    source_url: []const u8,
    source_sha256: []const u8,
    source_bytes: i64,
    source_commit: []const u8,
    qemu_version: []const u8,
    runner: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `candidate_command`.
pub fn candidateCommand(
    context: *Context,
    arguments: CandidateArguments,
) Error!void {
    const expected = try requireVariant(
        context,
        arguments.architecture,
        arguments.filesystem,
        arguments.flavor,
    );
    const asset = try realPath(context, arguments.asset);
    const asset_name = std.fs.path.basename(asset);
    if (!std.mem.eql(u8, asset_name, expected.asset_name)) return context.fail(
        "{s} asset must be {s}",
        .{ expected.key, expected.asset_name },
    );
    try document.requireSha256(context, arguments.validated_sha256, "validated SHA-256");
    const actual_sha256 = try hashFile(context, asset);
    if (!std.mem.eql(u8, &actual_sha256, arguments.validated_sha256)) return context.fail(
        "validated SHA-256 does not match the candidate",
        .{},
    );
    if (arguments.virtual_size != @as(i64, @intCast(expected.virtual_size))) {
        return context.fail(
            "candidate virtual size does not match the pinned profile",
            .{},
        );
    }
    const qemu_info_path = try realPath(context, arguments.qemu_info);
    if (!std.mem.eql(u8, parentOf(qemu_info_path), parentOf(asset))) return context.fail(
        "qemu-img validation input must be beside the candidate",
        .{},
    );
    const qemu_image = try loadQemuImageInfo(
        context,
        qemu_info_path,
        arguments.virtual_size,
    );
    if (!std.mem.eql(u8, arguments.source_name, expected.source_name)) return context.fail(
        "source filename does not match the pinned profile",
        .{},
    );
    if (!std.mem.eql(u8, arguments.source_sha256, expected.source_sha256)) {
        return context.fail("source SHA-256 does not match the pinned profile", .{});
    }
    try document.requireSha256(context, arguments.source_sha256, "source SHA-256");
    if (arguments.source_bytes <= 0) return context.fail(
        "source size must be positive",
        .{},
    );
    if (!contract.isCommitHex(arguments.source_commit)) return context.fail(
        "source commit must be a lowercase 40-character SHA",
        .{},
    );
    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    if (!std.mem.eql(u8, arguments.source_url, expected.sourceUrl(&url_buffer))) {
        return context.fail("source URL does not match the pinned profile", .{});
    }
    const qemu_version = document.trim(arguments.qemu_version);
    const runner = document.trim(arguments.runner);
    if (qemu_version.len == 0 or runner.len == 0) return context.fail(
        "QEMU version and runner must be recorded",
        .{},
    );
    const manifest_path = try realPath(context, arguments.package_manifest);
    const packages = try parsePackageManifest(context, manifest_path);
    var names: std.ArrayList([]const u8) = .empty;
    var installed_bytes: i64 = 0;
    for (packages) |package| {
        try names.append(context.arena, package.name);
        installed_bytes += package.installed_bytes;
    }
    try verifyPackageManifest(
        context,
        expected.filesystem,
        expected.flavor,
        names.items,
    );

    const reviewed = profiles.packageManifest(expected.filesystem, expected.flavor).?;
    const compressed_size = try regularFileSize(context, asset);
    const qemu_info_sha256 = try hashFile(context, qemu_info_path);

    var name_values: std.json.Array = .init(context.arena);
    for (names.items) |name| try name_values.append(.{ .string = name });

    var packages_object: std.json.ObjectMap = .empty;
    try packages_object.put(context.arena, "manifest_revision", .{ .integer = reviewed.revision });
    try packages_object.put(context.arena, "count", .{ .integer = @intCast(packages.len) });
    try packages_object.put(context.arena, "installed_bytes", .{ .integer = installed_bytes });
    try packages_object.put(context.arena, "names", .{ .array = name_values });

    var source_object: std.json.ObjectMap = .empty;
    try source_object.put(context.arena, "name", .{ .string = arguments.source_name });
    try source_object.put(context.arena, "url", .{ .string = arguments.source_url });
    try source_object.put(context.arena, "bytes", .{ .integer = arguments.source_bytes });
    try source_object.put(context.arena, "sha256", .{ .string = arguments.source_sha256 });

    var qemu_info_object: std.json.ObjectMap = .empty;
    try qemu_info_object.put(context.arena, "name", .{
        .string = std.fs.path.basename(qemu_info_path),
    });
    try qemu_info_object.put(context.arena, "sha256", .{
        .string = try context.arena.dupe(u8, &qemu_info_sha256),
    });

    var validation_object: std.json.ObjectMap = .empty;
    try validation_object.put(context.arena, "qemu_version", .{ .string = qemu_version });
    try validation_object.put(context.arena, "qemu_image", try qemu_image.toValue(context.arena));
    try validation_object.put(context.arena, "qemu_info", .{ .object = qemu_info_object });
    try validation_object.put(context.arena, "runner", .{ .string = runner });
    try validation_object.put(context.arena, "run_id", .{ .string = arguments.run_id });
    try validation_object.put(context.arena, "run_attempt", .{ .string = arguments.run_attempt });

    var root: std.json.ObjectMap = .empty;
    try root.put(context.arena, "schema", .{ .integer = profiles.candidate_schema });
    try root.put(context.arena, "type", .{ .string = candidate_type });
    try root.put(context.arena, "variant", .{ .string = expected.key });
    try root.put(context.arena, "architecture", .{ .string = expected.architecture });
    try root.put(context.arena, "filesystem", .{ .string = expected.filesystem });
    try root.put(context.arena, "flavor", .{ .string = expected.flavor });
    try root.put(context.arena, "asset_name", .{ .string = asset_name });
    try root.put(context.arena, "compressed_size", .{ .integer = @intCast(compressed_size) });
    try root.put(context.arena, "allocated_size", .{ .integer = qemu_image.allocated_size });
    try root.put(context.arena, "asset_sha256", .{
        .string = try context.arena.dupe(u8, &actual_sha256),
    });
    try root.put(context.arena, "virtual_size", .{ .integer = arguments.virtual_size });
    try root.put(context.arena, "packages", .{ .object = packages_object });
    try root.put(context.arena, "source", .{ .object = source_object });
    try root.put(context.arena, "source_commit", .{ .string = arguments.source_commit });
    try root.put(context.arena, "validation", .{ .object = validation_object });

    try writeDocument(context, arguments.output, .{ .object = root });
}

/// `write_json`: canonical bytes replacing the destination atomically.
pub fn writeDocument(context: *Context, path: []const u8, value: Value) Error!void {
    const bytes = json_document.canonicalAlloc(context.arena, value, .document) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return context.fail("cannot serialize {s}", .{path}),
        };
    file_support.writeAtomic(context.io, path, bytes) catch |err|
        return context.fail("cannot write {s}: {t}", .{ path, err });
}

pub fn writeText(context: *Context, path: []const u8, text: []const u8) Error!void {
    file_support.writeAtomic(context.io, path, text) catch |err|
        return context.fail("cannot write {s}: {t}", .{ path, err });
}

// ---- validate_candidate ---------------------------------------------------

pub const ValidatedCandidate = struct {
    value: Value,
    variant: *const profiles.Variant,
    asset_path: []const u8,
    compressed_size: i64,
    allocated_size: i64,

    pub fn object(self: ValidatedCandidate) std.json.ObjectMap {
        return self.value.object;
    }

    pub fn get(self: ValidatedCandidate, key: []const u8) ?Value {
        return self.value.object.get(key);
    }
};

/// `validate_candidate`: everything a candidate manifest claims, re-derived
/// from the artifacts beside it.
pub fn validateCandidate(
    context: *Context,
    manifest_path: []const u8,
    source_commit: []const u8,
) Error!ValidatedCandidate {
    const value = try readObject(context, manifest_path);
    const root = value.object;
    const parent = parentOf(manifest_path);

    if (document.integerOf(root.get("schema")) != profiles.candidate_schema) {
        return context.fail("{s}: unsupported schema", .{manifest_path});
    }
    if (!document.eqlString(root.get("type"), candidate_type)) return context.fail(
        "{s}: unexpected candidate type",
        .{manifest_path},
    );
    const key = document.stringOf(root.get("variant")) orelse return context.fail(
        "{s}: unexpected variant",
        .{manifest_path},
    );
    const expected = profiles.findVariant(key) orelse return context.fail(
        "{s}: unexpected variant",
        .{manifest_path},
    );
    for (&profiles.profile_keys) |profile_key| {
        const wanted = profiles.profileField(expected, profile_key).?;
        if (!document.eqlString(root.get(profile_key), wanted)) return context.fail(
            "{s}: {s} does not match profile",
            .{ manifest_path, profile_key },
        );
    }
    const virtual_size: i64 = @intCast(expected.virtual_size);
    if (document.integerOf(root.get("virtual_size")) != virtual_size) {
        return context.fail("{s}: virtual_size does not match profile", .{manifest_path});
    }
    const compressed_size = try document.requirePositiveInt(
        context,
        root.get("compressed_size"),
        "{s}: compressed size",
        .{manifest_path},
    );
    const allocated_size = try document.requirePositiveInt(
        context,
        root.get("allocated_size"),
        "{s}: allocated size",
        .{manifest_path},
    );
    if (allocated_size > virtual_size) return context.fail(
        "{s}: allocated size exceeds virtual size",
        .{manifest_path},
    );

    const validation = document.objectOf(root.get("validation")) orelse
        return context.fail("{s}: validation metadata is missing", .{manifest_path});
    const qemu_image = validation.get("qemu_image") orelse return context.fail(
        "{s}: qemu-img validation metadata is missing",
        .{manifest_path},
    );
    if (document.objectOf(qemu_image) == null) return context.fail(
        "{s}: qemu-img validation metadata is missing",
        .{manifest_path},
    );
    const expected_qemu_image = try (QemuImage{
        .virtual_size = virtual_size,
        .allocated_size = allocated_size,
    }).toValue(context.arena);
    if (!document.valueEql(qemu_image, expected_qemu_image)) return context.fail(
        "{s}: qemu-img size metadata mismatch",
        .{manifest_path},
    );

    const qemu_info = document.objectOf(validation.get("qemu_info")) orelse
        return context.fail("{s}: qemu-img validation input is missing", .{manifest_path});
    const qemu_info_name = document.stringOf(qemu_info.get("name")) orelse
        return context.fail(
            "{s}: invalid qemu-img validation input name",
            .{manifest_path},
        );
    if (!isBareFileName(qemu_info_name)) return context.fail(
        "{s}: invalid qemu-img validation input name",
        .{manifest_path},
    );
    const recorded_qemu_info_sha256 = document.stringOf(qemu_info.get("sha256")) orelse "";
    try requireSha256Labeled(
        context,
        recorded_qemu_info_sha256,
        "{s}: qemu-img validation input SHA-256",
        .{manifest_path},
    );
    const qemu_info_path = try joinPath(context, &.{ parent, qemu_info_name });
    if (!isRegularFile(context.io, qemu_info_path)) return context.fail(
        "{s}: qemu-img validation input is missing",
        .{manifest_path},
    );
    const qemu_info_sha256 = try hashFile(context, qemu_info_path);
    if (!std.mem.eql(u8, &qemu_info_sha256, recorded_qemu_info_sha256)) {
        return context.fail("{s}: qemu-img validation input mismatch", .{manifest_path});
    }
    const reloaded = try loadQemuImageInfo(context, qemu_info_path, virtual_size);
    if (!document.valueEql(
        try reloaded.toValue(context.arena),
        expected_qemu_image,
    )) return context.fail("{s}: qemu-img validation input changed", .{manifest_path});

    const source = document.objectOf(root.get("source")) orelse return context.fail(
        "{s}: source metadata is missing",
        .{manifest_path},
    );
    if (!document.eqlString(source.get("name"), expected.source_name)) {
        return context.fail("{s}: source name does not match profile", .{manifest_path});
    }
    if (!document.eqlString(source.get("sha256"), expected.source_sha256)) {
        return context.fail(
            "{s}: source sha256 does not match profile",
            .{manifest_path},
        );
    }
    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    if (!document.eqlString(source.get("url"), expected.sourceUrl(&url_buffer))) {
        return context.fail("{s}: source url does not match profile", .{manifest_path});
    }
    if (!document.eqlString(root.get("source_commit"), source_commit)) {
        return context.fail("{s}: source commit mismatch", .{manifest_path});
    }

    const asset_name = document.stringOf(root.get("asset_name")).?;
    const asset_path = try joinPath(context, &.{ parent, asset_name });
    if (!isRegularFile(context.io, asset_path)) return context.fail(
        "{s}: candidate asset is missing",
        .{manifest_path},
    );
    const asset_size = try regularFileSize(context, asset_path);
    if (asset_size != @as(u64, @intCast(compressed_size))) return context.fail(
        "{s}: candidate size mismatch",
        .{manifest_path},
    );
    const asset_sha256 = try hashFile(context, asset_path);
    if (!document.eqlString(root.get("asset_sha256"), &asset_sha256)) {
        return context.fail("{s}: candidate digest mismatch", .{manifest_path});
    }
    try document.requireSha256(
        context,
        document.stringOf(root.get("asset_sha256")),
        "candidate SHA-256",
    );
    try document.requireSha256(
        context,
        document.stringOf(source.get("sha256")),
        "source SHA-256",
    );

    const recorded = document.objectOf(root.get("packages")) orelse
        return context.fail("{s}: no recorded package manifest", .{manifest_path});
    const names = try recordedPackageNames(context, recorded, manifest_path);
    const reviewed = profiles.packageManifest(
        expected.filesystem,
        expected.flavor,
    ).?;
    if (document.integerOf(recorded.get("manifest_revision")) != reviewed.revision) {
        return context.fail(
            "{s}: package manifest revision does not match",
            .{manifest_path},
        );
    }
    if (document.integerOf(recorded.get("count")) != @as(i64, @intCast(names.len))) {
        return context.fail("{s}: package count does not match", .{manifest_path});
    }
    try verifyPackageManifest(context, expected.filesystem, expected.flavor, names);

    return .{
        .value = value,
        .variant = expected,
        .asset_path = asset_path,
        .compressed_size = compressed_size,
        .allocated_size = allocated_size,
    };
}

/// The recorded `packages.names` list, which must be a non-empty list of
/// strings before any of it can be checked against the reviewed contract.
pub fn recordedPackageNames(
    context: *Context,
    recorded: std.json.ObjectMap,
    manifest_path: []const u8,
) Error![]const []const u8 {
    const items = document.arrayOf(recorded.get("names")) orelse
        return context.fail("{s}: no recorded package manifest", .{manifest_path});
    if (items.items.len == 0) return context.fail(
        "{s}: no recorded package manifest",
        .{manifest_path},
    );
    var names: std.ArrayList([]const u8) = .empty;
    for (items.items) |item| {
        const name = document.stringOf(item) orelse return context.fail(
            "{s}: no recorded package manifest",
            .{manifest_path},
        );
        try names.append(context.arena, name);
    }
    return names.items;
}

fn requireSha256Labeled(
    context: *Context,
    value: []const u8,
    comptime label_fmt: []const u8,
    label_args: anytype,
) Error!void {
    if (!contract.isSha256Hex(value)) return context.fail(
        label_fmt ++ " must be a lowercase SHA-256",
        label_args,
    );
}

/// `Path(name).name == name`: a bare file name, not a path.
pub fn isBareFileName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    return true;
}

// ---- azure-result ---------------------------------------------------------

pub const AzureResultArguments = struct {
    manifest: []const u8,
    asset: []const u8,
    key: []const u8,
    source_commit: []const u8,
    vhd_sha256: []const u8,
    vhd_bytes: i64,
    vhd_current_size: i64,
    contracts: []const u8,
    location: []const u8,
    vm_size: []const u8,
    resource_group: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `azure_result_command`.
pub fn azureResultCommand(
    context: *Context,
    arguments: AzureResultArguments,
) Error!void {
    const manifest_path = try realPath(context, arguments.manifest);
    const candidate = try validateCandidate(
        context,
        manifest_path,
        arguments.source_commit,
    );
    if (!std.mem.eql(u8, candidate.variant.key, arguments.key)) return context.fail(
        "candidate variant does not match --key",
        .{},
    );
    const expected_contracts = profiles.azureContracts(candidate.variant.filesystem).?;

    // Independently verify the asset the caller points to is the same file the
    // candidate manifest describes -- the harness may pass a path that differs
    // from the one validateCandidate resolved (same file, different argument).
    const asset = try realPath(context, arguments.asset);
    const canonical_asset = try realPath(context, candidate.asset_path);
    if (!std.mem.eql(u8, asset, canonical_asset)) {
        const actual = try hashFile(context, asset);
        if (!document.eqlString(candidate.get("asset_sha256"), &actual)) {
            return context.fail("--asset does not match the candidate digest", .{});
        }
    }

    try document.requireSha256(context, arguments.vhd_sha256, "VHD SHA-256");
    const alignment: i64 = @intCast(azure_vhd.alignment);
    const footer: i64 = @intCast(azure_vhd.footer_bytes);
    if (arguments.vhd_current_size <= 0 or
        @mod(arguments.vhd_current_size, alignment) != 0 or
        arguments.vhd_bytes != arguments.vhd_current_size + footer)
    {
        return context.fail("VHD size evidence is inconsistent", .{});
    }

    if (!contractsMatch(arguments.contracts, expected_contracts)) return context.fail(
        "contracts do not match required Azure contracts",
        .{},
    );

    const location = try document.requireNonEmpty(context, arguments.location, "location");
    const vm_size = try document.requireNonEmpty(context, arguments.vm_size, "vm_size");
    const resource_group = try document.requireNonEmpty(
        context,
        arguments.resource_group,
        "resource_group",
    );
    const run_id = try document.requireNonEmpty(context, arguments.run_id, "run_id");
    const run_attempt = try document.requireNonEmpty(
        context,
        arguments.run_attempt,
        "run_attempt",
    );
    const validation = document.objectOf(candidate.get("validation")).?;
    if (!document.eqlString(validation.get("run_id"), run_id) or
        !document.eqlString(validation.get("run_attempt"), run_attempt))
    {
        return context.fail(
            "Azure result workflow identity does not match candidate validation",
            .{},
        );
    }

    var contract_values: std.json.Array = .init(context.arena);
    for (expected_contracts) |name| try contract_values.append(.{ .string = name });

    var workflow: std.json.ObjectMap = .empty;
    try workflow.put(context.arena, "run_id", .{ .string = run_id });
    try workflow.put(context.arena, "run_attempt", .{ .string = run_attempt });

    var root: std.json.ObjectMap = .empty;
    try root.put(context.arena, "schema", .{ .integer = profiles.candidate_schema });
    try root.put(context.arena, "type", .{ .string = azure_result_type });
    try root.put(context.arena, "variant", .{ .string = candidate.variant.key });
    try root.put(context.arena, "architecture", .{ .string = candidate.variant.architecture });
    try root.put(context.arena, "filesystem", .{ .string = candidate.variant.filesystem });
    try root.put(context.arena, "flavor", .{ .string = candidate.variant.flavor });
    try root.put(context.arena, "asset_name", .{ .string = candidate.variant.asset_name });
    try root.put(context.arena, "source_commit", .{ .string = arguments.source_commit });
    try root.put(context.arena, "qcow_sha256", candidate.get("asset_sha256").?);
    try root.put(context.arena, "qcow_virtual_size", .{
        .integer = @intCast(candidate.variant.virtual_size),
    });
    try root.put(context.arena, "qcow_allocated_size", .{ .integer = candidate.allocated_size });
    try root.put(context.arena, "qcow_compressed_size", .{ .integer = candidate.compressed_size });
    try root.put(context.arena, "derived_vhd_sha256", .{ .string = arguments.vhd_sha256 });
    try root.put(context.arena, "derived_vhd_bytes", .{ .integer = arguments.vhd_bytes });
    try root.put(context.arena, "derived_vhd_current_size", .{ .integer = arguments.vhd_current_size });
    try root.put(context.arena, "status", .{ .string = "success" });
    try root.put(context.arena, "location", .{ .string = location });
    try root.put(context.arena, "vm_size", .{ .string = vm_size });
    try root.put(context.arena, "resource_group", .{ .string = resource_group });
    try root.put(context.arena, "contracts", .{ .array = contract_values });
    try root.put(context.arena, "workflow", .{ .object = workflow });

    try writeDocument(context, arguments.output, .{ .object = root });
}

/// The comma-separated `--contracts` value, stripped element by element the
/// way the Python compared it against the required list.
pub fn contractsMatch(provided: []const u8, expected: []const []const u8) bool {
    var index: usize = 0;
    var parts = std.mem.splitScalar(u8, provided, ',');
    while (parts.next()) |raw| {
        if (index >= expected.len) return false;
        if (!std.mem.eql(u8, document.trim(raw), expected[index])) return false;
        index += 1;
    }
    return index == expected.len;
}

// ---- candidate-binding ----------------------------------------------------

pub const BindingArguments = struct {
    manifest: []const u8,
    asset: []const u8,
    key: []const u8,
    source_commit: []const u8,
    architecture: []const u8,
    filesystem: []const u8,
    flavor: []const u8,
    asset_name: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
};

/// `validate_candidate_binding` from the Azure acceptance harness: the
/// canonical candidate validation, plus the harness-specific bindings that the
/// artifact it is about to upload really is the one this workflow run built.
/// Emits the five values the harness reads back, one per line.
pub fn candidateBinding(
    context: *Context,
    arguments: BindingArguments,
    out: *std.Io.Writer,
) Error!void {
    const manifest_path = try realPath(context, arguments.manifest);
    const candidate = try validateCandidate(
        context,
        manifest_path,
        arguments.source_commit,
    );
    const requested = try realPath(context, arguments.asset);
    const canonical = try realPath(context, candidate.asset_path);
    if (!std.mem.eql(u8, requested, canonical)) return context.fail(
        "candidate asset path does not match manifest",
        .{},
    );
    if (!std.mem.eql(u8, std.fs.path.basename(requested), arguments.asset_name) or
        !document.eqlString(candidate.get("asset_name"), arguments.asset_name))
    {
        return context.fail("candidate asset name mismatch", .{});
    }
    if (!std.mem.eql(u8, candidate.variant.key, arguments.key)) return context.fail(
        "candidate variant mismatch: expected {s}",
        .{arguments.key},
    );
    if (!document.eqlString(candidate.get("architecture"), arguments.architecture)) {
        return context.fail("candidate architecture mismatch", .{});
    }
    if (!document.eqlString(candidate.get("filesystem"), arguments.filesystem)) {
        return context.fail("candidate filesystem mismatch", .{});
    }
    if (!document.eqlString(candidate.get("flavor"), arguments.flavor)) {
        return context.fail("candidate flavor mismatch", .{});
    }
    if (profiles.packageManifest(arguments.filesystem, arguments.flavor) == null) {
        return context.fail(
            "unsupported candidate filesystem/flavor combination",
            .{},
        );
    }

    const root = candidate.object();
    const compressed_size = document.integerOf(root.get("compressed_size"));
    if (compressed_size == null or compressed_size.? <= 0) return context.fail(
        "candidate compressed size is missing or invalid",
        .{},
    );
    const allocated_size = document.integerOf(root.get("allocated_size"));
    if (allocated_size == null or allocated_size.? <= 0) return context.fail(
        "candidate allocated size is missing or invalid",
        .{},
    );
    const virtual_size = document.integerOf(root.get("virtual_size"));
    if (virtual_size == null or virtual_size.? <= 0) return context.fail(
        "candidate virtual size is missing or invalid",
        .{},
    );
    const source = document.objectOf(root.get("source")) orelse return context.fail(
        "candidate source metadata is missing",
        .{},
    );
    const source_bytes = document.integerOf(source.get("bytes"));
    if (source_bytes == null or source_bytes.? <= 0) return context.fail(
        "candidate source size is missing or invalid",
        .{},
    );
    const packages = document.objectOf(root.get("packages")) orelse return context.fail(
        "candidate package manifest is missing",
        .{},
    );
    const installed_bytes = document.integerOf(packages.get("installed_bytes"));
    if (installed_bytes == null or installed_bytes.? <= 0) return context.fail(
        "candidate package installed size is missing or invalid",
        .{},
    );

    const recorded_path = try std.fmt.allocPrint(
        context.arena,
        "{s}.packages.txt",
        .{requested},
    );
    const manifest_file = try realPath(context, recorded_path);
    const installed = try parsePackageManifest(context, manifest_file);
    var names: std.ArrayList([]const u8) = .empty;
    var recorded_bytes: i64 = 0;
    for (installed) |package| {
        try names.append(context.arena, package.name);
        recorded_bytes += package.installed_bytes;
    }
    try verifyPackageManifest(
        context,
        arguments.filesystem,
        arguments.flavor,
        names.items,
    );
    const claimed = document.arrayOf(packages.get("names"));
    if (claimed == null or claimed.?.items.len != names.items.len) return context.fail(
        "candidate package manifest content does not match",
        .{},
    );
    for (claimed.?.items, names.items) |claimed_name, recorded_name| {
        if (!document.eqlString(claimed_name, recorded_name)) return context.fail(
            "candidate package manifest content does not match",
            .{},
        );
    }
    if (document.integerOf(packages.get("count")) != @as(i64, @intCast(names.items.len))) {
        return context.fail("candidate package manifest count does not match", .{});
    }
    if (recorded_bytes != installed_bytes.?) return context.fail(
        "candidate package manifest installed size does not match",
        .{},
    );

    const validation = document.objectOf(root.get("validation")) orelse
        return context.fail("candidate validation metadata is missing", .{});
    for ([_][]const u8{ "qemu_version", "runner", "run_id", "run_attempt" }) |field| {
        const text = document.stringOf(validation.get(field)) orelse
            return context.fail("candidate validation metadata is missing {s}", .{field});
        if (document.trim(text).len == 0) return context.fail(
            "candidate validation metadata is missing {s}",
            .{field},
        );
    }
    if (!document.eqlString(validation.get("runner"), candidate.variant.runner)) {
        return context.fail("candidate validation runner does not match profile", .{});
    }
    if (!document.eqlString(validation.get("run_id"), arguments.run_id) or
        !document.eqlString(validation.get("run_attempt"), arguments.run_attempt))
    {
        return context.fail("candidate validation workflow identity mismatch", .{});
    }

    out.print("{s}\n{d}\n{d}\n{d}\n{s}\n", .{
        document.stringOf(root.get("asset_sha256")).?,
        compressed_size.?,
        allocated_size.?,
        virtual_size.?,
        document.stringOf(root.get("architecture")).?,
    }) catch return error.OutOfMemory;
}

test "package records parse exactly the recorded grammar" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const record = parsePackageRecord("FreeBSD-runtime 15.1 2048").?;
    try std.testing.expectEqualStrings("FreeBSD-runtime", record.name);
    try std.testing.expectEqualStrings("15.1", record.version);
    try std.testing.expectEqual(@as(i64, 2048), record.installed_bytes);

    try std.testing.expectEqual(
        @as(?Package, null),
        parsePackageRecord("FreeBSD-runtime 15.1"),
    );
    try std.testing.expectEqual(@as(?Package, null), parsePackageRecord("a 1 x"));
    try std.testing.expectEqual(@as(?Package, null), parsePackageRecord("a 1 2 3"));
    try std.testing.expectEqual(@as(?Package, null), parsePackageRecord(""));
    try std.testing.expectEqual(@as(?Package, null), parsePackageRecord("a  2"));
}

test "python line splitting drops only the trailing newline" {
    var empty = splitPythonLines("");
    try std.testing.expectEqual(@as(?[]const u8, null), empty.next());

    var one = splitPythonLines("abc\n");
    try std.testing.expectEqualStrings("abc", one.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), one.next());

    var blank = splitPythonLines("abc\n\n");
    try std.testing.expectEqualStrings("abc", blank.next().?);
    try std.testing.expectEqualStrings("", blank.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), blank.next());

    var unterminated = splitPythonLines("abc");
    try std.testing.expectEqualStrings("abc", unterminated.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), unterminated.next());

    var carriage = splitPythonLines("abc\r\ndef\n");
    try std.testing.expectEqualStrings("abc", carriage.next().?);
    try std.testing.expectEqualStrings("def", carriage.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), carriage.next());
}

test "contract lists match only element for element" {
    const zfs = profiles.azureContracts("zfs").?;
    try std.testing.expect(contractsMatch(
        "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp," ++
            "serial-console,zfs-root,zpool-healthy,root-growth,gpt-healthy," ++
            "reboot-reconnect,instance-identity",
        zfs,
    ));
    try std.testing.expect(contractsMatch(
        " matching-architecture-gen2 , key-only-ssh ,agent-ready,hn0-dhcp," ++
            "serial-console,zfs-root,zpool-healthy,root-growth,gpt-healthy," ++
            "reboot-reconnect,instance-identity",
        zfs,
    ));
    try std.testing.expect(!contractsMatch("key-only-ssh,agent-ready", zfs));
    try std.testing.expect(!contractsMatch("", zfs));
    try std.testing.expect(!contractsMatch(
        "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp," ++
            "serial-console,zfs-root,zpool-healthy,root-growth,gpt-healthy," ++
            "reboot-reconnect,instance-identity,extra",
        zfs,
    ));
}

test "bare file names reject every path spelling" {
    try std.testing.expect(isBareFileName("qemu-img-info.json"));
    try std.testing.expect(!isBareFileName(""));
    try std.testing.expect(!isBareFileName("."));
    try std.testing.expect(!isBareFileName(".."));
    try std.testing.expect(!isBareFileName("a/b"));
    try std.testing.expect(!isBareFileName("dir/"));
}
