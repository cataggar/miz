//! Filesystem-facing commands of the Azure Linux 4 release tool.
//!
//! Native port of the command half of `scripts/azurelinux4_release.py`. The
//! contracts these commands enforce live in `contracts.zig` as pure functions;
//! everything here is the reading, digesting, staging, and writing around
//! them.
//!
//! Three rules hold throughout, and they are what make the tool safe to run
//! against artifacts a workflow downloaded:
//!
//! * every read is bounded before memory is committed and re-checked for
//!   replacement while it was in flight;
//! * every output document is written through the atomic stage-then-rename in
//!   the shared foundation, so no consumer ever reads a half-written
//!   manifest; and
//! * `stage` is transactional: an output directory it filled and then failed
//!   on is emptied again, leaving the exact state it started from, because a
//!   half-staged release directory is the one thing a retry must never find.

const std = @import("std");

const azure_vhd = @import("../azure_vhd.zig");
const contracts = @import("contracts.zig");
const release = @import("../release/root.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const Writer = std.Io.Writer;
const contract = release.contract;
const digest_support = release.digest;
const file_support = release.file;
const json_document = release.json_document;

pub const Diagnostic = contract.Diagnostic;

/// Upper bound on a published image or a derived VHD. The largest asset this
/// matrix produces is a 5 GiB virtual-size QCOW2 whose VHD form is 5 GiB plus
/// a footer; the bound is well clear of that and still finite.
pub const max_artifact_bytes: u64 = 64 * 1024 * 1024 * 1024;

/// Upper bound on one provenance file. Provenance holds documents and a build
/// log, never an image.
pub const max_provenance_file_bytes: u64 = 256 * 1024 * 1024;

/// Upper bound on a release document this repository writes. `candidate.json`
/// grows with the provenance file list, so it gets more room than the
/// foundation default while staying bounded.
pub const max_release_document_bytes: u64 = 8 * 1024 * 1024;

/// Upper bound on a document produced by Azure or the GitHub API.
pub const max_service_document_bytes: u64 = 16 * 1024 * 1024;

/// Upper bound on the number of entries any directory this tool walks may
/// hold. Provenance is tens of files and a release staging directory is four
/// images plus a manifest; a tree far past that is a mistake, not an input.
pub const max_directory_entries: usize = 100_000;

pub const CommandError = contracts.Error || json_document.CanonicalError || error{
    MissingAsset,
    UnknownKey,
    ArgumentMismatch,
    InvalidVirtualSize,
    CannotRead,
    NotAnObject,
    MissingProvenance,
    EmptyProvenance,
    PrivateKeyMaterial,
    ProvenanceMismatch,
    SizeMismatch,
    DigestMismatch,
    BuildValidationMissing,
    InvalidCandidateSet,
    ForbiddenSidecar,
    StagingDirectoryNotEmpty,
    StagingChangedBytes,
    AzureAcceptanceMismatch,
    MixedSigningIdentity,
    InvalidVhdEvidence,
    TooManyEntries,
    Io,
};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Best-effort absolute spelling of `path`, in the spirit of the Python's
/// `Path.resolve()` in a diagnostic. A path that cannot be resolved -- because
/// it does not exist, which is often exactly why it is being reported -- is
/// named as it was given.
pub fn displayPath(io: Io, path: []const u8, buffer: []u8) []const u8 {
    if (std.fs.path.isAbsolute(path)) return path;
    const length = Dir.cwd().realPathFile(io, ".", buffer) catch return path;
    const cwd = buffer[0..length];
    if (cwd.len + 1 + path.len > buffer.len) return path;
    buffer[cwd.len] = '/';
    @memcpy(buffer[cwd.len + 1 ..][0..path.len], path);
    return buffer[0 .. cwd.len + 1 + path.len];
}

fn basename(path: []const u8) []const u8 {
    return std.fs.path.basename(path);
}

fn join(allocator: Allocator, parts: []const []const u8) Allocator.Error![]u8 {
    return std.fs.path.join(allocator, parts);
}

// ---------------------------------------------------------------------------
// Directory listings
// ---------------------------------------------------------------------------

pub const Entry = struct {
    /// Path relative to the walked root, always with `/` separators.
    path: []const u8,
    kind: std.Io.File.Kind,
};

/// Every entry under `root`, sorted by relative path the way Python's
/// `sorted(root.rglob("*"))` orders them: byte-wise over the path text.
///
/// Symbolic links are reported with their own kind rather than followed, and
/// every caller treats an entry that is neither a regular file nor a directory
/// as a rejection: release provenance is files, and a link in it is something
/// nobody put there on purpose.
pub fn listTree(
    allocator: Allocator,
    io: Io,
    root: []const u8,
) !([]Entry) {
    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer entries.deinit(allocator);

    var walker = try directory.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entries.items.len >= max_directory_entries) return error.TooManyEntries;
        try entries.append(allocator, .{
            .path = try allocator.dupe(u8, entry.path),
            .kind = entry.kind,
        });
    }

    std.mem.sort(Entry, entries.items, {}, struct {
        fn lessThan(_: void, left: Entry, right: Entry) bool {
            return std.mem.lessThan(u8, left.path, right.path);
        }
    }.lessThan);
    return entries.toOwnedSlice(allocator);
}

fn hasSuffix(path: []const u8, suffix: []const u8) bool {
    return std.mem.endsWith(u8, path, suffix);
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// `provenance_records`: every provenance file, in sorted order, bound to its
/// size and digest, with private key material refused outright.
pub fn provenanceRecords(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    diagnostic: *Diagnostic,
) CommandError![]contracts.ProvenanceRecord {
    var display: [std.fs.max_path_bytes]u8 = undefined;
    const entries = listTree(allocator, io, root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManyEntries => return diagnostic.fail(
            error.TooManyEntries,
            "provenance directory holds too many entries: {s}",
            .{displayPath(io, root, &display)},
        ),
        else => return diagnostic.fail(
            error.MissingProvenance,
            "provenance directory is missing: {s}",
            .{displayPath(io, root, &display)},
        ),
    };

    var records: std.ArrayList(contracts.ProvenanceRecord) = .empty;
    for (entries) |entry| {
        switch (entry.kind) {
            .file => {},
            .directory => continue,
            else => return diagnostic.fail(
                error.MissingProvenance,
                "provenance entry is not a regular file: {s}",
                .{entry.path},
            ),
        }
        const full = try join(allocator, &.{ root, entry.path });
        const contents = file_support.readBounded(
            allocator,
            io,
            full,
            max_provenance_file_bytes,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return diagnostic.fail(
                error.CannotRead,
                "cannot read {s}: {s}",
                .{ full, @errorName(err) },
            ),
        };
        if (contracts.containsPrivateKey(contents)) return diagnostic.fail(
            error.PrivateKeyMaterial,
            "private key material is forbidden in provenance: {s}",
            .{full},
        );
        const hex = try allocator.dupe(u8, &digest_support.hexBytes(contents));
        try records.append(allocator, .{
            .path = entry.path,
            .bytes = contents.len,
            .sha256 = hex,
        });
    }
    if (records.items.len == 0) return diagnostic.fail(
        error.EmptyProvenance,
        "provenance directory is empty: {s}",
        .{displayPath(io, root, &display)},
    );
    return records.toOwnedSlice(allocator);
}

/// `validate_signing_provenance`: the read plus the contract.
pub fn signingBinding(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    entry: contracts.Entry,
    diagnostic: *Diagnostic,
) CommandError!Value {
    var name_buffer: [contracts.signing_provenance_name_capacity]u8 = undefined;
    const name = contracts.signingProvenanceName(
        &name_buffer,
        entry.architecture,
        entry.flavor,
    );
    const path = try join(allocator, &.{ root, name });
    // The document stays alive on `allocator`: the binding's strings point
    // into it, and the caller compares and writes them after this returns.
    var document = try json_document.readObject(
        allocator,
        io,
        path,
        max_release_document_bytes,
        diagnostic,
    );
    const binding = try contracts.bindSigningProvenance(
        allocator,
        &document.parsed.value.object,
        entry,
        try allocator.dupe(u8, name),
        diagnostic,
    );
    return binding.toValue(allocator);
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

const FileDigest = struct {
    hex: []const u8,
    size: u64,
};

fn hashArtifact(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) CommandError!FileDigest {
    const result = digest_support.hashFile(io, path, max_artifact_bytes) catch |err| {
        return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        );
    };
    return .{
        .hex = try allocator.dupe(u8, &result.hex),
        .size = result.size,
    };
}

fn isRegularFile(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .file;
}

// ---------------------------------------------------------------------------
// candidate
// ---------------------------------------------------------------------------

pub const CandidateArguments = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset: []const u8,
    validated_sha256: []const u8,
    virtual_size: i64,
    source_commit: []const u8,
    provenance_dir: []const u8,
    runner: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `candidate_command`: bind a freshly built asset to its digest, its size,
/// its provenance, and the signer that produced its UKIs.
pub fn candidate(
    allocator: Allocator,
    io: Io,
    arguments: CandidateArguments,
    diagnostic: *Diagnostic,
) CommandError!void {
    var display: [std.fs.max_path_bytes]u8 = undefined;
    if (!isRegularFile(io, arguments.asset)) return diagnostic.fail(
        error.MissingAsset,
        "candidate asset is missing: {s}",
        .{displayPath(io, arguments.asset, &display)},
    );
    const entry = contracts.lookup(arguments.key) orelse return diagnostic.fail(
        error.UnknownKey,
        "unknown candidate key: {s}",
        .{arguments.key},
    );
    if (!std.mem.eql(u8, arguments.architecture, entry.architecture) or
        !std.mem.eql(u8, arguments.flavor, entry.flavor))
    {
        return diagnostic.fail(
            error.ArgumentMismatch,
            "{s}: architecture/flavor arguments do not match",
            .{arguments.key},
        );
    }
    if (!std.mem.eql(u8, basename(arguments.asset), entry.asset_name)) {
        return diagnostic.fail(
            error.ArgumentMismatch,
            "{s}: expected asset {s}, got {s}",
            .{ arguments.key, entry.asset_name, basename(arguments.asset) },
        );
    }
    const source_commit = try contract.requireCommit(
        contracts.str(arguments.source_commit),
        "source_commit",
        diagnostic,
    );

    const records = try provenanceRecords(
        allocator,
        io,
        arguments.provenance_dir,
        diagnostic,
    );
    const signing = try signingBinding(
        allocator,
        io,
        arguments.provenance_dir,
        entry,
        diagnostic,
    );

    const asset_digest = try hashArtifact(allocator, io, arguments.asset, diagnostic);
    if (!std.mem.eql(u8, arguments.validated_sha256, asset_digest.hex)) {
        return diagnostic.fail(
            error.DigestMismatch,
            "{s}: build validation digest does not match candidate bytes",
            .{arguments.key},
        );
    }
    if (arguments.virtual_size <= 0) return diagnostic.fail(
        error.InvalidVirtualSize,
        "virtual size must be positive",
        .{},
    );

    const record_values = try contracts.provenanceRecordsValue(allocator, records);
    const provenance_digest = try contracts.provenanceDigest(allocator, record_values);
    const document = try contracts.object(allocator, &.{
        .{ "schema", contracts.int(1) },
        .{ "type", contracts.str("azurelinux4-candidate") },
        .{ "key", contracts.str(entry.key) },
        .{ "architecture", contracts.str(entry.architecture) },
        .{ "flavor", contracts.str(entry.flavor) },
        .{ "asset_name", contracts.str(entry.asset_name) },
        .{ "source_commit", contracts.str(source_commit) },
        .{ "sha256", contracts.str(asset_digest.hex) },
        .{ "bytes", contracts.int(@intCast(asset_digest.size)) },
        .{ "virtual_size", contracts.int(arguments.virtual_size) },
        .{ "build_validation", try contracts.object(allocator, &.{
            .{ "status", contracts.str("success") },
            .{ "validated_sha256", contracts.str(arguments.validated_sha256) },
            .{ "runner", contracts.str(arguments.runner) },
        }) },
        .{ "provenance", try contracts.object(allocator, &.{
            .{ "digest", contracts.str(try allocator.dupe(u8, &provenance_digest)) },
            .{ "files", record_values },
        }) },
        .{ "uki_signing", signing },
        .{ "workflow", try contracts.object(allocator, &.{
            .{ "run_id", contracts.str(arguments.run_id) },
            .{ "run_attempt", contracts.str(arguments.run_attempt) },
        }) },
    });

    json_document.writeDocument(allocator, io, arguments.output, document) catch |err| {
        return diagnostic.fail(
            error.Io,
            "cannot write {s}: {s}",
            .{ arguments.output, @errorName(err) },
        );
    };
}

// ---------------------------------------------------------------------------
// verify-candidate
// ---------------------------------------------------------------------------

/// A candidate manifest that has been proven against the bytes it describes.
/// The parsed document stays alive because `stage` reads more of it.
pub const VerifiedCandidate = struct {
    document: json_document.Document,
    entry: contracts.Entry,
    sha256: []const u8,
    bytes: u64,
    virtual_size: i64,
    uki_signing: Value,

    pub fn object(self: *const VerifiedCandidate) contracts.ObjectMap {
        return self.document.parsed.value.object;
    }

    pub fn deinit(self: *VerifiedCandidate) void {
        self.document.deinit();
        self.* = undefined;
    }
};

/// `verify_candidate`: re-derive everything `candidate.json` claims, from the
/// asset bytes to the provenance allowlist to the signer binding.
pub fn verifyCandidate(
    allocator: Allocator,
    io: Io,
    manifest_path: []const u8,
    asset_path: []const u8,
    key: ?[]const u8,
    source_commit: ?[]const u8,
    diagnostic: *Diagnostic,
) CommandError!VerifiedCandidate {
    var document = try json_document.readObject(
        allocator,
        io,
        manifest_path,
        max_release_document_bytes,
        diagnostic,
    );
    errdefer document.deinit();
    const map = &document.parsed.value.object;
    const entry = try contracts.validateIdentity(
        map,
        "azurelinux4-candidate",
        key,
        source_commit,
        diagnostic,
    );

    if (!std.mem.eql(u8, basename(asset_path), entry.asset_name) or
        !isRegularFile(io, asset_path))
    {
        return diagnostic.fail(
            error.MissingAsset,
            "{s}: exact candidate asset is missing",
            .{entry.key},
        );
    }
    var label: [128]u8 = undefined;
    const bound_digest = try contract.requireSha256(
        map.get("sha256"),
        std.fmt.bufPrint(&label, "{s} candidate digest", .{entry.key}) catch &label,
        diagnostic,
    );
    const asset_digest = try hashArtifact(allocator, io, asset_path, diagnostic);
    if (!std.mem.eql(u8, asset_digest.hex, bound_digest)) return diagnostic.fail(
        error.DigestMismatch,
        "{s}: candidate bytes do not match the bound digest",
        .{entry.key},
    );
    const bound_bytes = contracts.integerOrNull(map.get("bytes")) orelse -1;
    if (bound_bytes < 0 or @as(u64, @intCast(bound_bytes)) != asset_digest.size) {
        return diagnostic.fail(
            error.SizeMismatch,
            "{s}: candidate size mismatch",
            .{entry.key},
        );
    }
    const virtual_size = contracts.integerOrNull(map.get("virtual_size")) orelse 0;
    if (virtual_size <= 0) return diagnostic.fail(
        error.InvalidVirtualSize,
        "{s}: invalid virtual size",
        .{entry.key},
    );
    const build_validation = contracts.objectOrNull(map.get("build_validation")) orelse
        return diagnostic.fail(
            error.BuildValidationMissing,
            "{s}: build validation is not explicitly successful",
            .{entry.key},
        );
    if (!contracts.isString(build_validation.get("status"), "success")) {
        return diagnostic.fail(
            error.BuildValidationMissing,
            "{s}: build validation is not explicitly successful",
            .{entry.key},
        );
    }
    if (!contracts.isString(build_validation.get("validated_sha256"), bound_digest)) {
        return diagnostic.fail(
            error.BuildValidationMissing,
            "{s}: build validation did not validate published bytes",
            .{entry.key},
        );
    }

    const provenance = contracts.objectOrNull(map.get("provenance")) orelse
        return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: provenance is absent",
            .{entry.key},
        );
    _ = try contract.requireSha256(
        provenance.get("digest"),
        std.fmt.bufPrint(&label, "{s} provenance digest", .{entry.key}) catch &label,
        diagnostic,
    );
    const files = contracts.arrayOrNull(provenance.get("files")) orelse &.{};
    if (files.len == 0) return diagnostic.fail(
        error.ProvenanceMismatch,
        "{s}: provenance file bindings are absent",
        .{entry.key},
    );

    const provenance_root = try join(allocator, &.{
        std.fs.path.dirname(manifest_path) orelse ".",
        "internal-provenance",
    });
    try verifyProvenanceBindings(
        allocator,
        io,
        provenance_root,
        entry,
        files,
        diagnostic,
    );
    const rebuilt = contracts.provenanceDigest(
        allocator,
        provenance.get("files").?,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // A record carrying a value the canonical writer will not emit cannot
        // be one this tool wrote, so its digest cannot be the bound one.
        error.UnsupportedFloat => return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: aggregate provenance digest mismatch",
            .{entry.key},
        ),
    };
    if (!contracts.isString(provenance.get("digest"), &rebuilt)) {
        return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: aggregate provenance digest mismatch",
            .{entry.key},
        );
    }

    const signing = map.get("uki_signing") orelse Value{ .null = {} };
    if (contracts.objectOrNull(signing) == null) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "{s}: UKI signing binding is absent",
        .{entry.key},
    );
    const actual_signing = try signingBinding(
        allocator,
        io,
        provenance_root,
        entry,
        diagnostic,
    );
    if (!contracts.jsonEql(signing, actual_signing)) return diagnostic.fail(
        error.InvalidSigningProvenance,
        "{s}: UKI signing binding does not match provenance",
        .{entry.key},
    );

    return .{
        .document = document,
        .entry = entry,
        .sha256 = bound_digest,
        .bytes = asset_digest.size,
        .virtual_size = virtual_size,
        .uki_signing = signing,
    };
}

/// The provenance half of `verify_candidate`: every bound record must name a
/// real file with the exact size and digest recorded, hold no key material,
/// and the bound set must be exactly the set on disk.
fn verifyProvenanceBindings(
    allocator: Allocator,
    io: Io,
    provenance_root: []const u8,
    entry: contracts.Entry,
    files: []const Value,
    diagnostic: *Diagnostic,
) CommandError!void {
    var bound: std.StringHashMapUnmanaged(void) = .empty;
    defer bound.deinit(allocator);

    for (files) |record| {
        const fields = contracts.objectOrNull(record) orelse return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: invalid provenance record",
            .{entry.key},
        );
        const relative = contracts.stringOrNull(fields.get("path")) orelse "";
        if (!isBoundProvenancePath(relative) or bound.contains(relative)) {
            return diagnostic.fail(
                error.ProvenanceMismatch,
                "{s}: invalid provenance path",
                .{entry.key},
            );
        }
        const path = try join(allocator, &.{ provenance_root, relative });
        if (isRegularFile(io, path)) {
            const contents = file_support.readBounded(
                allocator,
                io,
                path,
                max_provenance_file_bytes,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return diagnostic.fail(
                    error.CannotRead,
                    "cannot read {s}: {s}",
                    .{ path, @errorName(err) },
                ),
            };
            defer allocator.free(contents);
            if (contracts.containsPrivateKey(contents)) return diagnostic.fail(
                error.PrivateKeyMaterial,
                "{s}: private key material is forbidden in provenance",
                .{entry.key},
            );
            const recorded = contracts.integerOrNull(fields.get("bytes")) orelse -1;
            if (recorded < 0 or @as(u64, @intCast(recorded)) != contents.len) {
                return diagnostic.fail(
                    error.ProvenanceMismatch,
                    "{s}: provenance file/size mismatch for {s}",
                    .{ entry.key, relative },
                );
            }
            if (!contracts.isString(
                fields.get("sha256"),
                &digest_support.hexBytes(contents),
            )) return diagnostic.fail(
                error.ProvenanceMismatch,
                "{s}: provenance digest mismatch for {s}",
                .{ entry.key, relative },
            );
        } else {
            return diagnostic.fail(
                error.ProvenanceMismatch,
                "{s}: provenance file/size mismatch for {s}",
                .{ entry.key, relative },
            );
        }
        try bound.put(allocator, relative, {});
    }

    const entries = listTree(allocator, io, provenance_root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // A provenance directory that is gone is an allowlist mismatch: the
        // bound set is non-empty and the actual set is empty.
        else => return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: provenance file allowlist mismatch",
            .{entry.key},
        ),
    };
    var actual: usize = 0;
    for (entries) |item| {
        switch (item.kind) {
            .file => {},
            .directory => continue,
            else => return diagnostic.fail(
                error.ProvenanceMismatch,
                "{s}: provenance file allowlist mismatch",
                .{entry.key},
            ),
        }
        actual += 1;
        if (!bound.contains(item.path)) return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: provenance file allowlist mismatch",
            .{entry.key},
        );
    }
    if (actual != bound.count()) return diagnostic.fail(
        error.ProvenanceMismatch,
        "{s}: provenance file allowlist mismatch",
        .{entry.key},
    );
}

/// A bound provenance path must be relative, non-empty, and must not climb out
/// of the provenance directory.
fn isBoundProvenancePath(relative: []const u8) bool {
    if (relative.len == 0) return false;
    if (std.fs.path.isAbsolute(relative)) return false;
    var components = std.mem.splitAny(u8, relative, "/\\");
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// azure-result
// ---------------------------------------------------------------------------

pub const AzureResultArguments = struct {
    manifest: []const u8,
    asset: []const u8,
    vhd: []const u8,
    vhd_current_size: i64,
    key: []const u8,
    source_commit: []const u8,
    location: []const u8,
    vm_size: []const u8,
    resource_group: []const u8,
    image_version_id: []const u8,
    uefi_request: []const u8,
    uefi_response: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `azure_result_command`: bind the candidate, the derived VHD, and the exact
/// custom UEFI settings Azure accepted into one acceptance document.
pub fn azureResult(
    allocator: Allocator,
    io: Io,
    arguments: AzureResultArguments,
    diagnostic: *Diagnostic,
) CommandError!void {
    var candidate_result = try verifyCandidate(
        allocator,
        io,
        arguments.manifest,
        arguments.asset,
        arguments.key,
        arguments.source_commit,
        diagnostic,
    );
    defer candidate_result.deinit();
    const entry = candidate_result.entry;

    var display: [std.fs.max_path_bytes]u8 = undefined;
    if (!isRegularFile(io, arguments.vhd)) return diagnostic.fail(
        error.MissingAsset,
        "derived VHD is missing: {s}",
        .{displayPath(io, arguments.vhd, &display)},
    );
    const vhd_digest = try hashArtifact(allocator, io, arguments.vhd, diagnostic);
    if (arguments.vhd_current_size <= 0 or
        @rem(arguments.vhd_current_size, @as(i64, @intCast(azure_vhd.alignment))) != 0 or
        vhd_digest.size != @as(u64, @intCast(arguments.vhd_current_size)) + azure_vhd.footer_bytes)
    {
        return diagnostic.fail(
            error.InvalidVhdEvidence,
            "derived VHD current-size evidence is inconsistent",
            .{},
        );
    }

    var request = try json_document.readObject(
        allocator,
        io,
        arguments.uefi_request,
        max_service_document_bytes,
        diagnostic,
    );
    defer request.deinit();
    var response = try json_document.readObject(
        allocator,
        io,
        arguments.uefi_response,
        max_service_document_bytes,
        diagnostic,
    );
    defer response.deinit();

    const signing = contracts.objectOrNull(candidate_result.uki_signing).?;
    const certificate_sha256 = contracts.stringOrNull(
        signing.get("certificate_sha256"),
    ).?;
    const request_uefi = try contracts.validateAzureGalleryUefiSettings(
        allocator,
        &request.parsed.value.object,
        &response.parsed.value.object,
        certificate_sha256,
        diagnostic,
    );

    const asset_digest = try hashArtifact(allocator, io, arguments.asset, diagnostic);
    const map = candidate_result.object();
    const document = try contracts.object(allocator, &.{
        .{ "schema", contracts.int(1) },
        .{ "type", contracts.str("azurelinux4-azure-acceptance") },
        .{ "key", contracts.str(entry.key) },
        .{ "architecture", contracts.str(entry.architecture) },
        .{ "flavor", contracts.str(entry.flavor) },
        .{ "asset_name", contracts.str(entry.asset_name) },
        .{ "source_commit", map.get("source_commit").? },
        .{ "qcow_sha256", contracts.str(candidate_result.sha256) },
        .{ "azure_accepted_sha256", contracts.str(asset_digest.hex) },
        .{ "derived_vhd_sha256", contracts.str(vhd_digest.hex) },
        .{ "derived_vhd_bytes", contracts.int(@intCast(vhd_digest.size)) },
        .{ "derived_vhd_current_size", contracts.int(arguments.vhd_current_size) },
        .{ "certificate_sha256", contracts.str(certificate_sha256) },
        .{
            "signing_certificate_sha256",
            signing.get("signing_certificate_sha256") orelse .{ .null = {} },
        },
        .{
            "fallback_uki_sha256",
            signing.get("fallback_uki_sha256") orelse .{ .null = {} },
        },
        .{ "image_version_id", contracts.str(arguments.image_version_id) },
        .{ "uefi_settings", request_uefi },
        .{ "status", contracts.str("success") },
        .{ "location", contracts.str(arguments.location) },
        .{ "vm_size", contracts.str(arguments.vm_size) },
        .{ "resource_group", contracts.str(arguments.resource_group) },
        .{ "contracts", try contracts.azureContractsValue(allocator) },
        .{ "workflow", try contracts.object(allocator, &.{
            .{ "run_id", contracts.str(arguments.run_id) },
            .{ "run_attempt", contracts.str(arguments.run_attempt) },
        }) },
    });

    json_document.writeDocument(allocator, io, arguments.output, document) catch |err| {
        return diagnostic.fail(
            error.Io,
            "cannot write {s}: {s}",
            .{ arguments.output, @errorName(err) },
        );
    };
}

// ---------------------------------------------------------------------------
// stage
// ---------------------------------------------------------------------------

pub const StageArguments = struct {
    candidates: []const u8,
    azure_results: []const u8,
    source_commit: []const u8,
    release_tag: []const u8,
    output: []const u8,
    notes: []const u8,
};

/// One published asset, as it is recorded in `publish-manifest.json` and
/// rendered in the release notes.
const StagedAsset = struct {
    entry: contracts.Entry,
    sha256: []const u8,
    bytes: u64,
    virtual_size: i64,
    build_runner: Value,
    provenance_digest: Value,
    certificate_sha256: []const u8,
    signing_certificate_sha256: []const u8,
    fallback_uki_sha256: []const u8,
    azure_location: Value,
    azure_vm_size: Value,
    derived_vhd_sha256: Value,
    derived_vhd_bytes: i64,
    derived_vhd_current_size: i64,
    azure_image_version_id: Value,
};

/// Everything `stage` created, so a failure can put the tree back exactly as
/// it found it. Staging is the last step before publication: a directory left
/// holding three of four images is indistinguishable, to a later run, from one
/// a human filled in by hand.
const StagingTransaction = struct {
    allocator: Allocator,
    io: Io,
    created_directory: ?[]const u8 = null,
    files: std.ArrayList([]const u8) = .empty,

    fn track(self: *StagingTransaction, path: []const u8) Allocator.Error!void {
        try self.files.append(self.allocator, path);
    }

    fn commit(self: *StagingTransaction) void {
        self.files.deinit(self.allocator);
        self.* = undefined;
    }

    /// Best effort by construction: rollback runs while a failure is already
    /// being reported, so a path that cannot be removed must not replace the
    /// diagnostic that explains why anything is being removed at all.
    fn rollback(self: *StagingTransaction) void {
        var index = self.files.items.len;
        while (index > 0) {
            index -= 1;
            Dir.cwd().deleteFile(self.io, self.files.items[index]) catch {};
        }
        if (self.created_directory) |directory| {
            Dir.cwd().deleteDir(self.io, directory) catch {};
        }
        self.files.deinit(self.allocator);
        self.* = undefined;
    }
};

/// `stage_command`: prove the complete four-by-four matrix, hard-link the four
/// published images into an empty staging directory, and write the publish
/// manifest and release notes.
pub fn stage(
    allocator: Allocator,
    io: Io,
    arguments: StageArguments,
    diagnostic: *Diagnostic,
) CommandError!void {
    var transaction: StagingTransaction = .{ .allocator = allocator, .io = io };
    errdefer transaction.rollback();
    try stageInner(allocator, io, arguments, &transaction, diagnostic);
    transaction.commit();
}

fn stageInner(
    allocator: Allocator,
    io: Io,
    arguments: StageArguments,
    transaction: *StagingTransaction,
    diagnostic: *Diagnostic,
) CommandError!void {
    const source_commit = try contract.requireCommit(
        contracts.str(arguments.source_commit),
        "source_commit",
        diagnostic,
    );

    const candidate_entries = try readTree(
        allocator,
        io,
        arguments.candidates,
        diagnostic,
    );
    const azure_entries = try readTree(
        allocator,
        io,
        arguments.azure_results,
        diagnostic,
    );
    for ([_][]const Entry{ candidate_entries, azure_entries }) |group| {
        for (group) |item| {
            if (hasSuffix(item.path, ".sha256")) return diagnostic.fail(
                error.ForbiddenSidecar,
                "SHA-256 sidecar files are forbidden",
                .{},
            );
        }
    }

    const candidates = try findDocuments(
        allocator,
        io,
        arguments.candidates,
        candidate_entries,
        "candidate.json",
        diagnostic,
    );
    const azure_results = try findDocuments(
        allocator,
        io,
        arguments.azure_results,
        azure_entries,
        "azure-result.json",
        diagnostic,
    );
    var qcow_count: usize = 0;
    for (candidate_entries) |item| {
        if (hasSuffix(item.path, ".qcow2")) qcow_count += 1;
    }
    if (qcow_count != contracts.release_order.len) return diagnostic.fail(
        error.InvalidCandidateSet,
        "expected exactly four candidate QCOW2 files, found {d}",
        .{qcow_count},
    );

    try prepareStagingDirectory(io, arguments.output, transaction, diagnostic);

    var staged: std.ArrayList(StagedAsset) = .empty;
    // Each verified candidate's document backs the values the staged record
    // carries, so the documents outlive the loop and are released only once
    // the manifest and the notes have been written from them.
    var verified_documents: std.ArrayList(VerifiedCandidate) = .empty;
    defer {
        for (verified_documents.items) |*document| document.deinit();
        verified_documents.deinit(allocator);
    }
    var release_certificate_sha256: ?[]const u8 = null;
    var release_signing_certificate_sha256: ?[]const u8 = null;
    var release_signing_provider: ?Value = null;

    for (contracts.release_order) |entry| {
        const found = candidates.get(entry.key).?;
        _ = try contracts.validateIdentity(
            &found.document.parsed.value.object,
            "azurelinux4-candidate",
            entry.key,
            source_commit,
            diagnostic,
        );
        const asset_path = try join(allocator, &.{
            std.fs.path.dirname(found.path) orelse ".",
            entry.asset_name,
        });
        try verified_documents.append(allocator, try verifyCandidate(
            allocator,
            io,
            found.path,
            asset_path,
            entry.key,
            source_commit,
            diagnostic,
        ));
        const verified = &verified_documents.items[verified_documents.items.len - 1];

        const azure = azure_results.get(entry.key).?;
        const azure_map = &azure.document.parsed.value.object;
        _ = try contracts.validateIdentity(
            azure_map,
            "azurelinux4-azure-acceptance",
            entry.key,
            source_commit,
            diagnostic,
        );
        var label: [128]u8 = undefined;
        const bound_digest = try contract.requireSha256(
            verified.object().get("sha256"),
            std.fmt.bufPrint(&label, "{s} candidate digest", .{entry.key}) catch &label,
            diagnostic,
        );
        if (!contracts.isString(azure_map.get("status"), "success")) {
            return diagnostic.fail(
                error.AzureAcceptanceMismatch,
                "{s}: Azure acceptance is not explicitly successful",
                .{entry.key},
            );
        }
        if (!contracts.isString(azure_map.get("qcow_sha256"), bound_digest) or
            !contracts.isString(azure_map.get("azure_accepted_sha256"), bound_digest))
        {
            return diagnostic.fail(
                error.AzureAcceptanceMismatch,
                "{s}: Azure acceptance did not validate published bytes",
                .{entry.key},
            );
        }
        const signing = contracts.objectOrNull(verified.uki_signing) orelse
            return diagnostic.fail(
                error.InvalidSigningProvenance,
                "{s}: UKI signing binding is absent",
                .{entry.key},
            );
        const certificate_sha256 = try contract.requireSha256(
            signing.get("certificate_sha256"),
            std.fmt.bufPrint(
                &label,
                "{s} signing certificate fingerprint",
                .{entry.key},
            ) catch &label,
            diagnostic,
        );
        const fallback_uki_sha256 = try contract.requireSha256(
            signing.get("fallback_uki_sha256"),
            std.fmt.bufPrint(&label, "{s} fallback UKI digest", .{entry.key}) catch &label,
            diagnostic,
        );
        const signing_certificate_sha256 = try contract.requireSha256(
            signing.get("signing_certificate_sha256"),
            std.fmt.bufPrint(
                &label,
                "{s} Artifact Signing leaf certificate fingerprint",
                .{entry.key},
            ) catch &label,
            diagnostic,
        );
        const signing_provider = signing.get("provider") orelse Value{ .null = {} };
        if (contracts.objectOrNull(signing_provider) == null) return diagnostic.fail(
            error.InvalidSigningProvenance,
            "{s}: Artifact Signing provider identity is absent",
            .{entry.key},
        );
        if (!contracts.isString(azure_map.get("certificate_sha256"), certificate_sha256) or
            !contracts.isString(
                azure_map.get("signing_certificate_sha256"),
                signing_certificate_sha256,
            ) or
            !contracts.isString(
                azure_map.get("fallback_uki_sha256"),
                fallback_uki_sha256,
            ))
        {
            return diagnostic.fail(
                error.AzureAcceptanceMismatch,
                "{s}: Azure acceptance did not bind the signed UKI identity",
                .{entry.key},
            );
        }
        _ = try contracts.validateAzureUefiSettings(
            allocator,
            azure_map.get("uefi_settings"),
            certificate_sha256,
            diagnostic,
        );
        const image_version_id = contracts.stringOrNull(
            azure_map.get("image_version_id"),
        ) orelse "";
        if (!std.mem.startsWith(u8, image_version_id, "/subscriptions/")) {
            return diagnostic.fail(
                error.AzureAcceptanceMismatch,
                "{s}: Azure gallery image-version identity is absent",
                .{entry.key},
            );
        }
        if (release_certificate_sha256) |shared| {
            if (!std.mem.eql(u8, shared, certificate_sha256)) return diagnostic.fail(
                error.MixedSigningIdentity,
                "release candidates do not share one UKI signing certificate",
                .{},
            );
        } else release_certificate_sha256 = certificate_sha256;
        if (release_signing_certificate_sha256) |shared| {
            if (!std.mem.eql(u8, shared, signing_certificate_sha256) or
                !contracts.jsonEql(release_signing_provider.?, signing_provider))
            {
                return diagnostic.fail(
                    error.MixedSigningIdentity,
                    "release candidates do not share one Artifact Signing identity",
                    .{},
                );
            }
        } else {
            release_signing_certificate_sha256 = signing_certificate_sha256;
            release_signing_provider = signing_provider;
        }
        _ = try contract.requireSha256(
            azure_map.get("derived_vhd_sha256"),
            std.fmt.bufPrint(&label, "{s} VHD digest", .{entry.key}) catch &label,
            diagnostic,
        );
        if (!contracts.hasExactContracts(azure_map.get("contracts"))) {
            return diagnostic.fail(
                error.AzureAcceptanceMismatch,
                "{s}: Azure contract results are absent",
                .{entry.key},
            );
        }
        const derived_vhd_bytes = contracts.integerOrNull(
            azure_map.get("derived_vhd_bytes"),
        ) orelse -1;
        const derived_vhd_current_size = contracts.integerOrNull(
            azure_map.get("derived_vhd_current_size"),
        ) orelse -1;
        if (derived_vhd_current_size <= 0 or
            @rem(derived_vhd_current_size, @as(i64, @intCast(azure_vhd.alignment))) != 0 or
            derived_vhd_bytes != derived_vhd_current_size +
                @as(i64, @intCast(azure_vhd.footer_bytes)))
        {
            return diagnostic.fail(
                error.InvalidVhdEvidence,
                "{s}: derived VHD size binding is absent",
                .{entry.key},
            );
        }
        const location = contracts.stringOrNull(azure_map.get("location")) orelse "";
        if (location.len == 0) return diagnostic.fail(
            error.AzureAcceptanceMismatch,
            "{s}: Azure location is absent",
            .{entry.key},
        );
        const vm_size = contracts.stringOrNull(azure_map.get("vm_size")) orelse "";
        if (vm_size.len == 0) return diagnostic.fail(
            error.AzureAcceptanceMismatch,
            "{s}: Azure VM size is absent",
            .{entry.key},
        );

        const destination = try join(allocator, &.{ arguments.output, entry.asset_name });
        try publishAsset(allocator, io, asset_path, destination, transaction, diagnostic);
        const staged_digest = try hashArtifact(allocator, io, destination, diagnostic);
        if (!std.mem.eql(u8, staged_digest.hex, bound_digest)) return diagnostic.fail(
            error.StagingChangedBytes,
            "{s}: staging changed candidate bytes",
            .{entry.key},
        );

        const build_validation = contracts.objectOrNull(
            verified.object().get("build_validation"),
        ) orelse return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: validated metadata changed type",
            .{entry.key},
        );
        const provenance = contracts.objectOrNull(
            verified.object().get("provenance"),
        ) orelse return diagnostic.fail(
            error.ProvenanceMismatch,
            "{s}: validated metadata changed type",
            .{entry.key},
        );

        try staged.append(allocator, .{
            .entry = entry,
            .sha256 = try allocator.dupe(u8, bound_digest),
            .bytes = staged_digest.size,
            .virtual_size = verified.virtual_size,
            .build_runner = build_validation.get("runner") orelse .{ .null = {} },
            .provenance_digest = provenance.get("digest") orelse .{ .null = {} },
            .certificate_sha256 = try allocator.dupe(u8, certificate_sha256),
            .signing_certificate_sha256 = try allocator.dupe(u8, signing_certificate_sha256),
            .fallback_uki_sha256 = try allocator.dupe(u8, fallback_uki_sha256),
            .azure_location = azure_map.get("location").?,
            .azure_vm_size = azure_map.get("vm_size").?,
            .derived_vhd_sha256 = azure_map.get("derived_vhd_sha256").?,
            .derived_vhd_bytes = derived_vhd_bytes,
            .derived_vhd_current_size = derived_vhd_current_size,
            .azure_image_version_id = azure_map.get("image_version_id").?,
        });
    }

    var assets: std.json.Array = .init(allocator);
    for (staged.items) |item| {
        try assets.append(try contracts.object(allocator, &.{
            .{ "key", contracts.str(item.entry.key) },
            .{ "architecture", contracts.str(item.entry.architecture) },
            .{ "flavor", contracts.str(item.entry.flavor) },
            .{ "asset_name", contracts.str(item.entry.asset_name) },
            .{ "sha256", contracts.str(item.sha256) },
            .{ "bytes", contracts.int(@intCast(item.bytes)) },
            .{ "virtual_size", contracts.int(item.virtual_size) },
            .{ "build_runner", item.build_runner },
            .{ "provenance_digest", item.provenance_digest },
            .{ "certificate_sha256", contracts.str(item.certificate_sha256) },
            .{
                "signing_certificate_sha256",
                contracts.str(item.signing_certificate_sha256),
            },
            .{ "fallback_uki_sha256", contracts.str(item.fallback_uki_sha256) },
            .{ "azure_location", item.azure_location },
            .{ "azure_vm_size", item.azure_vm_size },
            .{ "derived_vhd_sha256", item.derived_vhd_sha256 },
            .{ "derived_vhd_bytes", contracts.int(item.derived_vhd_bytes) },
            .{
                "derived_vhd_current_size",
                contracts.int(item.derived_vhd_current_size),
            },
            .{ "azure_image_version_id", item.azure_image_version_id },
        }));
    }

    const manifest = try contracts.object(allocator, &.{
        .{ "schema", contracts.int(1) },
        .{ "release_tag", contracts.str(arguments.release_tag) },
        .{ "source_commit", contracts.str(source_commit) },
        .{ "certificate_sha256", contracts.str(release_certificate_sha256.?) },
        .{
            "signing_certificate_sha256",
            contracts.str(release_signing_certificate_sha256.?),
        },
        .{ "signing_provider", release_signing_provider.? },
        .{ "assets", Value{ .array = assets } },
    });
    const manifest_path = try join(allocator, &.{ arguments.output, "publish-manifest.json" });
    try transaction.track(manifest_path);
    json_document.writeDocument(allocator, io, manifest_path, manifest) catch |err| {
        return diagnostic.fail(
            error.Io,
            "cannot write {s}: {s}",
            .{ manifest_path, @errorName(err) },
        );
    };

    const notes = try renderNotes(allocator, .{
        .source_commit = source_commit,
        .certificate_sha256 = release_certificate_sha256.?,
        .signing_certificate_sha256 = release_signing_certificate_sha256.?,
        .assets = staged.items,
    });
    try transaction.track(arguments.notes);
    file_support.writeAtomic(io, arguments.notes, notes) catch |err| {
        return diagnostic.fail(
            error.Io,
            "cannot write {s}: {s}",
            .{ arguments.notes, @errorName(err) },
        );
    };
}

fn readTree(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    diagnostic: *Diagnostic,
) CommandError![]Entry {
    var display: [std.fs.max_path_bytes]u8 = undefined;
    return listTree(allocator, io, root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManyEntries => diagnostic.fail(
            error.TooManyEntries,
            "release directory holds too many entries: {s}",
            .{displayPath(io, root, &display)},
        ),
        else => diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ displayPath(io, root, &display), @errorName(err) },
        ),
    };
}

const FoundDocument = struct {
    path: []const u8,
    document: json_document.Document,
};

/// `find_documents`: exactly four documents of the named kind, one per
/// candidate key, with no duplicate and no stranger.
fn findDocuments(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    entries: []const Entry,
    filename: []const u8,
    diagnostic: *Diagnostic,
) CommandError!std.StringHashMapUnmanaged(FoundDocument) {
    var paths: std.ArrayList([]const u8) = .empty;
    for (entries) |item| {
        if (item.kind != .file) continue;
        if (!std.mem.eql(u8, basename(item.path), filename)) continue;
        try paths.append(allocator, try join(allocator, &.{ root, item.path }));
    }
    if (paths.items.len != contracts.release_order.len) {
        var display: [std.fs.max_path_bytes]u8 = undefined;
        return diagnostic.fail(
            error.InvalidCandidateSet,
            "expected exactly four {s} files under {s}, found {d}",
            .{ filename, displayPath(io, root, &display), paths.items.len },
        );
    }

    var found: std.StringHashMapUnmanaged(FoundDocument) = .empty;
    for (paths.items) |path| {
        var document = try json_document.readObject(
            allocator,
            io,
            path,
            max_release_document_bytes,
            diagnostic,
        );
        const key = contracts.stringOrNull(document.parsed.value.object.get("key")) orelse
            return diagnostic.fail(
                error.InvalidCandidateSet,
                "duplicate or invalid key in {s}",
                .{path},
            );
        if (found.contains(key)) return diagnostic.fail(
            error.InvalidCandidateSet,
            "duplicate or invalid key in {s}",
            .{path},
        );
        try found.put(allocator, key, .{ .path = path, .document = document });
    }
    for (contracts.release_order) |entry| {
        if (!found.contains(entry.key)) return diagnostic.fail(
            error.InvalidCandidateSet,
            "{s} candidate set is not exact",
            .{filename},
        );
    }
    if (found.count() != contracts.release_order.len) return diagnostic.fail(
        error.InvalidCandidateSet,
        "{s} candidate set is not exact",
        .{filename},
    );
    return found;
}

/// The staging directory must be empty, and if this run creates it, a failure
/// removes it again.
fn prepareStagingDirectory(
    io: Io,
    output: []const u8,
    transaction: *StagingTransaction,
    diagnostic: *Diagnostic,
) CommandError!void {
    var display: [std.fs.max_path_bytes]u8 = undefined;
    if (Dir.cwd().openDir(io, output, .{ .iterate = true })) |existing| {
        var directory = existing;
        defer directory.close(io);
        var iterator = directory.iterate();
        const first = iterator.next(io) catch |err| return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ displayPath(io, output, &display), @errorName(err) },
        );
        if (first != null) return diagnostic.fail(
            error.StagingDirectoryNotEmpty,
            "staging directory is not empty: {s}",
            .{displayPath(io, output, &display)},
        );
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ displayPath(io, output, &display), @errorName(err) },
        ),
    }
    Dir.cwd().createDirPath(io, output) catch |err| return diagnostic.fail(
        error.Io,
        "cannot create {s}: {s}",
        .{ displayPath(io, output, &display), @errorName(err) },
    );
    transaction.created_directory = output;
}

/// `os.link` with a copy fallback: a hard link keeps a multi-gigabyte image
/// from being written twice, and a filesystem that will not link it still
/// publishes.
fn publishAsset(
    allocator: Allocator,
    io: Io,
    source: []const u8,
    destination: []const u8,
    transaction: *StagingTransaction,
    diagnostic: *Diagnostic,
) CommandError!void {
    _ = allocator;
    try transaction.track(destination);
    Dir.hardLink(Dir.cwd(), source, Dir.cwd(), destination, io, .{}) catch {
        Dir.copyFile(Dir.cwd(), source, Dir.cwd(), destination, io, .{}) catch |err| {
            return diagnostic.fail(
                error.Io,
                "cannot stage {s}: {s}",
                .{ destination, @errorName(err) },
            );
        };
    };
}

// ---------------------------------------------------------------------------
// Release notes
// ---------------------------------------------------------------------------

const NotesInput = struct {
    source_commit: []const u8,
    certificate_sha256: []const u8,
    signing_certificate_sha256: []const u8,
    assets: []const StagedAsset,
};

/// The published release notes, byte for byte as the Python emitted them.
/// These are the only place a published SHA-256 appears, so their shape is
/// part of the release contract rather than presentation.
fn renderNotes(allocator: Allocator, input: NotesInput) Allocator.Error![]u8 {
    var text: Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    // The only way an allocating writer fails is that its allocation did.
    writeNotes(&text.writer, input) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

fn writeNotes(out: *Writer, input: NotesInput) Writer.Error!void {
    try out.print(
        "Azure Linux 4.0 generalized Gen2 images built from the accepted source commit " ++
            "`{s}`. Every published QCOW2 passed hosted structural validation and " ++
            "protected-environment native validation on a matching Azure architecture.\n",
        .{input.source_commit},
    );
    try out.writeAll("\n");
    try out.print(
        "All UKIs are trusted through enrolled leaf SHA-256 `{s}`.\n",
        .{input.certificate_sha256},
    );
    try out.print(
        "Artifact Signing leaf certificate SHA-256: `{s}`.\n",
        .{input.signing_certificate_sha256},
    );
    try out.writeAll("\n");
    try out.writeAll(
        "| Asset | SHA-256 | UKI SHA-256 | File size | Virtual size | Azure validation " ++
            "| Derived VHD evidence (not published) |\n",
    );
    try out.writeAll("| --- | --- | --- | ---: | ---: | --- | --- |\n");
    for (input.assets) |item| {
        try out.print(
            "| `{s}` | `{s}` | `{s}` | {s} | {s} | `{s}` / `{s}` | " ++
                "`{s}`; current {d} bytes; file {d} bytes |\n",
            .{
                item.entry.asset_name,
                item.sha256,
                item.fallback_uki_sha256,
                contract.formatMib(item.bytes).slice(),
                contract.formatMib(@intCast(item.virtual_size)).slice(),
                jsonText(item.azure_location),
                jsonText(item.azure_vm_size),
                jsonText(item.derived_vhd_sha256),
                item.derived_vhd_current_size,
                item.derived_vhd_bytes,
            },
        );
    }
    try out.writeAll("\n");
    try out.writeAll(
        "The **full** images boot systemd and use cloud-init for account/key provisioning, " ++
            "WALinuxAgent for Azure Ready/extensions, and `sshd.service`. The **core** images " ++
            "boot `mizinit`, provision through `azagent`, and directly supervise OpenSSH. " ++
            "Core therefore requires a public SSH key in the Azure provisioning profile.\n",
    );
    try out.writeAll("\n");
    try out.writeAll(
        "Acceptance required signed UKIs, Azure Trusted Launch with Secure Boot and vTPM, " ++
            "the exact signer in UEFI db, kernel lockdown, " ++
            "module trust, key-only SSH, agent Ready, runtime architecture/flavor identity, " ++
            "root growth on an enlarged OS disk, temporary-resource-disk policy, " ++
            "managed-data-disk policy, and reboot/reconnect. Candidate and derived-VHD hashes " ++
            "were checked at every " ++
            "handoff; temporary VHDs and Azure resources were deleted.\n",
    );
    try out.writeAll("\n");
    try out.writeAll(
        "**No checksum sidecar assets are published**; SHA-256 digests are recorded only " ++
            "in these notes and the workflow job summary.\n",
    );
    try out.writeAll("\n");
    try out.writeAll("Internal provenance bindings:\n");
    try out.writeAll("\n");
    for (input.assets) |item| {
        try out.print(
            "- `{s}`: provenance `{s}`; hosted build on `{s}`\n",
            .{
                item.entry.asset_name,
                jsonText(item.provenance_digest),
                jsonText(item.build_runner),
            },
        );
    }
}

/// A validated string field rendered into notes. Every caller has already
/// proven its field is a string; `None` is the spelling Python would have
/// produced for anything else, so a defect stays visible rather than silently
/// rendering as empty.
fn jsonText(value: Value) []const u8 {
    return contracts.stringOrNull(value) orelse "None";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TempTree = @import("../release/testing.zig").TempTree;

test "release notes render the published table and provenance list" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const assets = [_]StagedAsset{.{
        .entry = contracts.lookup("x86_64-full").?,
        .sha256 = "9" ** 64,
        .bytes = 360_667_136,
        .virtual_size = 5_368_709_120,
        .build_runner = contracts.str("runner-x86_64"),
        .provenance_digest = contracts.str("7" ** 64),
        .certificate_sha256 = "1" ** 64,
        .signing_certificate_sha256 = "4" ** 64,
        .fallback_uki_sha256 = "3" ** 64,
        .azure_location = contracts.str("eastus2"),
        .azure_vm_size = contracts.str("Standard_D2ds_v5"),
        .derived_vhd_sha256 = contracts.str("9" ** 64),
        .derived_vhd_bytes = 1_049_088,
        .derived_vhd_current_size = 1_048_576,
        .azure_image_version_id = contracts.str("/subscriptions/test"),
    }};
    const notes = try renderNotes(allocator, .{
        .source_commit = "a" ** 40,
        .certificate_sha256 = "1" ** 64,
        .signing_certificate_sha256 = "4" ** 64,
        .assets = &assets,
    });

    try std.testing.expect(std.mem.indexOf(u8, notes, "| Asset | SHA-256 | UKI SHA-256 " ++
        "| File size | Virtual size | Azure validation " ++
        "| Derived VHD evidence (not published) |") != null);
    try std.testing.expect(std.mem.indexOf(u8, notes, "| Bytes |") == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "| `AzureLinux-4.0-x86_64.qcow2` | `" ++ "9" ** 64 ++ "` | `" ++ "3" ** 64 ++
            "` | 344.0 MiB | 5120.0 MiB | `eastus2` / `Standard_D2ds_v5` | `" ++
            "9" ** 64 ++ "`; current 1048576 bytes; file 1049088 bytes |",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "No checksum sidecar assets are published",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "- `AzureLinux-4.0-x86_64.qcow2`: provenance `" ++ "7" ** 64 ++
            "`; hosted build on `runner-x86_64`",
    ) != null);
    try std.testing.expect(std.mem.endsWith(u8, notes, "\n"));
}

test "bound provenance paths refuse absolute and climbing spellings" {
    try std.testing.expect(isBoundProvenancePath("inputs.txt"));
    try std.testing.expect(isBoundProvenancePath("nested/build.log"));
    try std.testing.expect(!isBoundProvenancePath(""));
    try std.testing.expect(!isBoundProvenancePath("/etc/shadow"));
    try std.testing.expect(!isBoundProvenancePath("../escape"));
    try std.testing.expect(!isBoundProvenancePath("nested/../../escape"));
}

test "listTree sorts by path and reports entry kinds" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "listing");
    var nested_buffer: [TempTree.max_path_len]u8 = undefined;
    const nested = tree.path(&nested_buffer, "listing/nested");
    try Dir.cwd().createDirPath(io, nested);
    var file_buffer: [TempTree.max_path_len]u8 = undefined;
    try Dir.cwd().writeFile(io, .{
        .sub_path = tree.path(&file_buffer, "listing/zeta.txt"),
        .data = "z",
    });
    try Dir.cwd().writeFile(io, .{
        .sub_path = tree.path(&file_buffer, "listing/nested/alpha.txt"),
        .data = "a",
    });

    const entries = try listTree(allocator, io, root);
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("nested", entries[0].path);
    try std.testing.expectEqual(std.Io.File.Kind.directory, entries[0].kind);
    try std.testing.expectEqualStrings("nested/alpha.txt", entries[1].path);
    try std.testing.expectEqualStrings("zeta.txt", entries[2].path);
}

test "provenance records bind every file and refuse key material" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "provenance");
    try Dir.cwd().createDirPath(io, root);
    var file_buffer: [TempTree.max_path_len]u8 = undefined;
    const inputs = tree.path(&file_buffer, "provenance/inputs.txt");
    try Dir.cwd().writeFile(io, .{ .sub_path = inputs, .data = "x86_64-full\n" });

    const records = try provenanceRecords(allocator, io, root, &diagnostic);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqualStrings("inputs.txt", records[0].path);
    try std.testing.expectEqual(@as(u64, 12), records[0].bytes);
    try std.testing.expectEqualStrings(
        &digest_support.hexBytes("x86_64-full\n"),
        records[0].sha256,
    );

    try Dir.cwd().writeFile(io, .{
        .sub_path = inputs,
        .data = "-----BEGIN PRIVATE KEY-----\nsecret\n",
    });
    try std.testing.expectError(error.PrivateKeyMaterial, provenanceRecords(
        allocator,
        io,
        root,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        diagnostic.message(),
        "private key material is forbidden in provenance: ",
    ));

    var empty_buffer: [TempTree.max_path_len]u8 = undefined;
    const empty = tree.path(&empty_buffer, "empty-provenance");
    try Dir.cwd().createDirPath(io, empty);
    try std.testing.expectError(error.EmptyProvenance, provenanceRecords(
        allocator,
        io,
        empty,
        &diagnostic,
    ));

    var absent_buffer: [TempTree.max_path_len]u8 = undefined;
    const absent = tree.path(&absent_buffer, "absent-provenance");
    try std.testing.expectError(error.MissingProvenance, provenanceRecords(
        allocator,
        io,
        absent,
        &diagnostic,
    ));
}

/// A complete, deterministic release matrix on disk: four candidate bundles
/// with provenance and signing documents, and four Azure acceptance results
/// bound to them. It is built by the real commands rather than by hand, so a
/// test that mutates one byte of it is testing what the release actually
/// produces.
const Fixture = struct {
    allocator: Allocator,
    io: Io,
    tree: TempTree,
    base: []const u8,
    candidates: []const u8,
    azure: []const u8,
    diagnostic: Diagnostic = .{},

    const source_commit = "a" ** 40;
    const certificate = "miz test certificate DER";
    const signing_leaf = "4" ** 64;
    const operation_id = "00000000-0000-4000-8000-000000000001";
    const vhd_current_size = azure_vhd.alignment;

    const Options = struct {
        certificate: []const u8 = Fixture.certificate,
        signing_leaf: []const u8 = Fixture.signing_leaf,
        virtual_size: i64 = 1024,
    };

    fn create(allocator: Allocator, io: Io) !Fixture {
        var tree = TempTree.create();
        var buffer: [TempTree.max_path_len]u8 = undefined;
        const base = try allocator.dupe(u8, tree.path(&buffer, "release"));
        return .{
            .allocator = allocator,
            .io = io,
            .tree = tree,
            .base = base,
            .candidates = try std.fmt.allocPrint(allocator, "{s}/candidates", .{base}),
            .azure = try std.fmt.allocPrint(allocator, "{s}/azure", .{base}),
        };
    }

    fn deinit(self: *Fixture) void {
        self.tree.deinit();
        self.* = undefined;
    }

    fn path(self: *Fixture, comptime fmt: []const u8, args: anytype) ![]const u8 {
        const relative = try std.fmt.allocPrint(self.allocator, fmt, args);
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.base, relative });
    }

    fn write(self: *Fixture, target: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(target)) |parent| {
            try Dir.cwd().createDirPath(self.io, parent);
        }
        try Dir.cwd().writeFile(self.io, .{ .sub_path = target, .data = data });
    }

    fn read(self: *Fixture, target: []const u8) ![]u8 {
        return file_support.readBounded(self.allocator, self.io, target, 1 << 20);
    }

    fn signingDocument(self: *Fixture, entry: contracts.Entry, options: Options) ![]u8 {
        const encoded = try contracts.encodeBase64Alloc(
            self.allocator,
            options.certificate,
        );
        const fingerprint = digest_support.hexBytes(options.certificate);
        return std.fmt.allocPrint(self.allocator,
            \\{{"schema": 1, "type": "miz-uki-signing", "architecture": "{s}",
            \\ "flavor": "{s}", "signer_mode": "external-command",
            \\ "certificate_sha256": "{s}", "certificate_der_base64": "{s}",
            \\ "certificate_details": "subject=CN=miz test signer",
            \\ "provider": {{"name": "azure-artifact-signing",
            \\  "endpoint": "https://wus.codesigning.azure.net",
            \\  "account": "cataggar", "profile": "miz-uki",
            \\  "signing_certificate_sha256": "{s}"}},
            \\ "signature_verification": "success",
            \\ "files": [
            \\  {{"path": "EFI/Linux/miz-{s}.efi", "unsigned_sha256": "{s}",
            \\    "signed_sha256": "{s}", "finalized_sha256": "{s}",
            \\    "signed_bytes": 4096, "signing_operation_id": "{s}",
            \\    "signing_certificate_sha256": "{s}"}},
            \\  {{"path": "{s}", "unsigned_sha256": "{s}",
            \\    "signed_sha256": "{s}", "finalized_sha256": "{s}",
            \\    "signed_bytes": 4096, "signing_operation_id": "{s}",
            \\    "signing_certificate_sha256": "{s}"}}]}}
        , .{
            entry.architecture,   entry.flavor,
            &fingerprint,         encoded,
            options.signing_leaf, entry.key,
            "2" ** 64,            "3" ** 64,
            "3" ** 64,            operation_id,
            options.signing_leaf, entry.fallbackUkiPath(),
            "2" ** 64,            "3" ** 64,
            "3" ** 64,            operation_id,
            options.signing_leaf,
        });
    }

    fn uefiPayload(self: *Fixture, options: Options) ![]u8 {
        const encoded = try contracts.encodeBase64Alloc(
            self.allocator,
            options.certificate,
        );
        return std.fmt.allocPrint(self.allocator,
            \\{{"properties": {{"securityProfile": {{"uefiSettings": {{
            \\ "signatureTemplateNames": ["{s}"],
            \\ "additionalSignatures": {{"db": [{{"type": "x509",
            \\   "value": ["{s}"]}}]}}}}}}}}}}
        , .{ contracts.gallery_signature_template, encoded });
    }

    fn makeBundle(self: *Fixture, entry: contracts.Entry, options: Options) !void {
        const asset = try self.path("candidates/{s}/{s}", .{ entry.key, entry.asset_name });
        const contents = try std.fmt.allocPrint(self.allocator, "{s}\n", .{entry.key});
        try self.write(asset, contents);

        const provenance = try self.path(
            "candidates/{s}/internal-provenance",
            .{entry.key},
        );
        try self.write(
            try std.fmt.allocPrint(self.allocator, "{s}/inputs.txt", .{provenance}),
            contents,
        );
        var name_buffer: [contracts.signing_provenance_name_capacity]u8 = undefined;
        const signing_name = contracts.signingProvenanceName(
            &name_buffer,
            entry.architecture,
            entry.flavor,
        );
        try self.write(
            try std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}",
                .{ provenance, signing_name },
            ),
            try self.signingDocument(entry, options),
        );

        const manifest = try self.path("candidates/{s}/candidate.json", .{entry.key});
        const digest = digest_support.hexBytes(contents);
        try candidate(self.allocator, self.io, .{
            .key = entry.key,
            .architecture = entry.architecture,
            .flavor = entry.flavor,
            .asset = asset,
            .validated_sha256 = &digest,
            .virtual_size = options.virtual_size,
            .source_commit = source_commit,
            .provenance_dir = provenance,
            .runner = try std.fmt.allocPrint(
                self.allocator,
                "runner-{s}",
                .{entry.architecture},
            ),
            .run_id = "1",
            .run_attempt = "1",
            .output = manifest,
        }, &self.diagnostic);

        const vhd = try self.path("azure/{s}/temporary.vhd", .{entry.key});
        const zeros = try self.allocator.alloc(u8, vhd_current_size + azure_vhd.footer_bytes);
        @memset(zeros, 0);
        try self.write(vhd, zeros);
        self.allocator.free(zeros);

        const payload = try self.uefiPayload(options);
        const request = try self.path("azure/{s}/uefi-request.json", .{entry.key});
        const response = try self.path("azure/{s}/uefi-response.json", .{entry.key});
        try self.write(request, payload);
        try self.write(response, payload);

        try azureResult(self.allocator, self.io, .{
            .manifest = manifest,
            .asset = asset,
            .vhd = vhd,
            .vhd_current_size = @intCast(vhd_current_size),
            .key = entry.key,
            .source_commit = source_commit,
            .location = "eastus2",
            .vm_size = "Standard_D2ds_v5",
            .resource_group = try std.fmt.allocPrint(
                self.allocator,
                "rg-{s}",
                .{entry.key},
            ),
            .image_version_id = try std.fmt.allocPrint(
                self.allocator,
                "/subscriptions/test/gallery/{s}/versions/1.0.0",
                .{entry.key},
            ),
            .uefi_request = request,
            .uefi_response = response,
            .run_id = "1",
            .run_attempt = "1",
            .output = try self.path("azure/{s}/azure-result.json", .{entry.key}),
        }, &self.diagnostic);
        try Dir.cwd().deleteFile(self.io, vhd);
    }

    fn makeAll(self: *Fixture) !void {
        for (contracts.release_order) |entry| try self.makeBundle(entry, .{});
    }

    const Staged = struct { output: []const u8, notes: []const u8 };

    fn stageAll(self: *Fixture) !Staged {
        const output = try self.path("staged", .{});
        const notes = try self.path("notes.md", .{});
        try Dir.cwd().createDirPath(self.io, self.base);
        try stage(self.allocator, self.io, .{
            .candidates = self.candidates,
            .azure_results = self.azure,
            .source_commit = source_commit,
            .release_tag = "AzureLinux-4.0-20260814",
            .output = output,
            .notes = notes,
        }, &self.diagnostic);
        return .{ .output = output, .notes = notes };
    }

    /// Rewrites one field of a JSON document that the matrix has already
    /// produced, which is how every mutation test reaches a state the
    /// commands themselves would never write.
    fn mutate(
        self: *Fixture,
        target: []const u8,
        key: []const u8,
        value: contracts.Value,
    ) !void {
        const text = try self.read(target);
        var parsed = try std.json.parseFromSlice(
            contracts.Value,
            self.allocator,
            text,
            .{},
        );
        defer parsed.deinit();
        try parsed.value.object.put(self.allocator, key, value);
        const encoded = try json_document.canonicalAlloc(
            self.allocator,
            parsed.value,
            .document,
        );
        try self.write(target, encoded);
    }
};

fn expectStageFails(fixture: *Fixture) !void {
    if (fixture.stageAll()) |_| {
        return error.StageUnexpectedlySucceeded;
    } else |_| {}
}

test "stage requires and copies exactly four bound assets" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var fixture = try Fixture.create(arena.allocator(), io);
    defer fixture.deinit();
    try fixture.makeAll();

    const staged = try fixture.stageAll();
    const manifest_text = try fixture.read(
        try std.fmt.allocPrint(
            arena.allocator(),
            "{s}/publish-manifest.json",
            .{staged.output},
        ),
    );
    var manifest = try std.json.parseFromSlice(
        contracts.Value,
        arena.allocator(),
        manifest_text,
        .{},
    );
    defer manifest.deinit();
    const assets = manifest.value.object.get("assets").?.array.items;
    try std.testing.expectEqual(@as(usize, 4), assets.len);
    for (assets, contracts.release_order) |asset, entry| {
        try std.testing.expect(contracts.isString(
            asset.object.get("asset_name"),
            entry.asset_name,
        ));
        try std.testing.expect(contracts.isString(
            asset.object.get("fallback_uki_sha256"),
            "3" ** 64,
        ));
        try std.testing.expectEqual(
            contracts.integerOrNull(asset.object.get("derived_vhd_bytes")).?,
            contracts.integerOrNull(asset.object.get("derived_vhd_current_size")).? +
                @as(i64, @intCast(azure_vhd.footer_bytes)),
        );
    }
    try std.testing.expect(contracts.isString(
        manifest.value.object.get("certificate_sha256"),
        &digest_support.hexBytes(Fixture.certificate),
    ));
    try std.testing.expect(contracts.isString(
        manifest.value.object.get("signing_certificate_sha256"),
        Fixture.signing_leaf,
    ));

    // The four images themselves are in the staging directory, and nothing
    // else is.
    const entries = try listTree(arena.allocator(), io, staged.output);
    try std.testing.expectEqual(@as(usize, 5), entries.len);
    for (contracts.release_order) |entry| {
        var found = false;
        for (entries) |item| {
            if (std.mem.eql(u8, item.path, entry.asset_name)) found = true;
        }
        try std.testing.expect(found);
    }

    // The manifest and the notes carry values read out of each candidate
    // document, which the staging loop must therefore keep alive.
    for (assets, contracts.release_order) |asset, entry| {
        const runner = try std.fmt.allocPrint(
            arena.allocator(),
            "runner-{s}",
            .{entry.architecture},
        );
        try std.testing.expect(contracts.isString(
            asset.object.get("build_runner"),
            runner,
        ));
        const provenance_digest = contracts.stringOrNull(
            asset.object.get("provenance_digest"),
        ) orelse "";
        try std.testing.expect(contract.isSha256Hex(provenance_digest));
    }

    const notes = try fixture.read(staged.notes);
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "No checksum sidecar assets are published",
    ) != null);
    for (assets, contracts.release_order) |asset, entry| {
        const line = try std.fmt.allocPrint(
            arena.allocator(),
            "- `{s}`: provenance `{s}`; hosted build on `runner-{s}`",
            .{
                entry.asset_name,
                contracts.stringOrNull(asset.object.get("provenance_digest")).?,
                entry.architecture,
            },
        );
        try std.testing.expect(std.mem.indexOf(u8, notes, line) != null);
    }
}

test "the candidate document records build validation, not local acceptance" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var fixture = try Fixture.create(arena.allocator(), io);
    defer fixture.deinit();
    const entry = contracts.lookup("x86_64-full").?;
    try fixture.makeBundle(entry, .{});

    const text = try fixture.read(
        try fixture.path("candidates/{s}/candidate.json", .{entry.key}),
    );
    var document = try std.json.parseFromSlice(
        contracts.Value,
        arena.allocator(),
        text,
        .{},
    );
    defer document.deinit();
    const build_validation = document.value.object.get("build_validation").?;
    try std.testing.expect(contracts.isString(
        build_validation.object.get("status"),
        "success",
    ));
    try std.testing.expect(document.value.object.get("local_acceptance") == null);
    try std.testing.expect(document.value.object.get("uki_signing") != null);
}

test "stage refuses an incomplete or unbound Azure matrix" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try Dir.cwd().deleteFile(
            io,
            try fixture.path("azure/aarch64-core/azure-result.json", .{}),
        );
        try expectStageFails(&fixture);
    }
    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try fixture.mutate(
            try fixture.path("azure/x86_64-full/azure-result.json", .{}),
            "azure_accepted_sha256",
            contracts.str("0" ** 64),
        );
        try expectStageFails(&fixture);
        try std.testing.expectEqualStrings(
            "x86_64-full: Azure acceptance did not validate published bytes",
            fixture.diagnostic.message(),
        );
    }
    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try fixture.mutate(
            try fixture.path("azure/x86_64-full/azure-result.json", .{}),
            "derived_vhd_current_size",
            contracts.int(@intCast(Fixture.vhd_current_size + azure_vhd.alignment)),
        );
        try expectStageFails(&fixture);
        try std.testing.expectEqualStrings(
            "x86_64-full: derived VHD size binding is absent",
            fixture.diagnostic.message(),
        );
    }
}

test "stage refuses a checksum sidecar anywhere in the inputs" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var fixture = try Fixture.create(arena.allocator(), io);
    defer fixture.deinit();
    try fixture.makeAll();
    try fixture.write(
        try fixture.path("candidates/forbidden.sha256", .{}),
        "0" ** 64,
    );
    try expectStageFails(&fixture);
    try std.testing.expectEqualStrings(
        "SHA-256 sidecar files are forbidden",
        fixture.diagnostic.message(),
    );
}

test "stage refuses tampered or missing internal provenance" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try fixture.write(
            try fixture.path(
                "candidates/x86_64-full/internal-provenance/inputs.txt",
                .{},
            ),
            "tampered\n",
        );
        try expectStageFails(&fixture);
    }
    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try Dir.cwd().deleteFile(io, try fixture.path(
            "candidates/x86_64-full/internal-provenance/uki-signing-full-x86_64.json",
            .{},
        ));
        try expectStageFails(&fixture);
    }
}

test "stage refuses private key material in provenance in every encoding" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { file: []const u8, data: []const u8 }{
        .{ .file = "inputs.txt", .data = "-----BEGIN PRIVATE KEY-----\nsecret\n" },
        .{
            .file = "inputs.txt",
            .data = "\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00",
        },
        .{
            .file = "inputs.txt",
            .data = "\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
        },
        .{
            .file = "build.log",
            .data = "diagnostic output\n" ++
                "\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
        },
        .{ .file = "inputs.txt", .data = "\x30\x08\x02\x01\x03\x30\x03\x06\x01\x2a" },
    };
    for (cases) |case| {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        try fixture.makeAll();
        try fixture.write(
            try fixture.path(
                "candidates/x86_64-full/internal-provenance/{s}",
                .{case.file},
            ),
            case.data,
        );
        try expectStageFails(&fixture);
    }
}

test "stage refuses a release that does not share one signing identity" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        for (contracts.release_order) |entry| {
            try fixture.makeBundle(entry, .{
                .certificate = if (std.mem.eql(u8, entry.key, "aarch64-core"))
                    "different certificate"
                else
                    Fixture.certificate,
            });
        }
        try expectStageFails(&fixture);
        try std.testing.expectEqualStrings(
            "release candidates do not share one UKI signing certificate",
            fixture.diagnostic.message(),
        );
    }
    {
        var fixture = try Fixture.create(arena.allocator(), io);
        defer fixture.deinit();
        for (contracts.release_order) |entry| {
            try fixture.makeBundle(entry, .{
                .signing_leaf = if (std.mem.eql(u8, entry.key, "aarch64-core"))
                    "5" ** 64
                else
                    Fixture.signing_leaf,
            });
        }
        try expectStageFails(&fixture);
        try std.testing.expectEqualStrings(
            "release candidates do not share one Artifact Signing identity",
            fixture.diagnostic.message(),
        );
    }
}

test "a failed stage leaves the staging directory exactly as it found it" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var fixture = try Fixture.create(arena.allocator(), io);
    defer fixture.deinit();
    try fixture.makeAll();
    // The last candidate in publication order fails, so three images have
    // already been linked into the staging directory when it does.
    try fixture.mutate(
        try fixture.path("azure/aarch64-core/azure-result.json", .{}),
        "status",
        contracts.str("failure"),
    );

    try expectStageFails(&fixture);
    try std.testing.expectEqualStrings(
        "aarch64-core: Azure acceptance is not explicitly successful",
        fixture.diagnostic.message(),
    );
    const output = try fixture.path("staged", .{});
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, output, .{}),
    );
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, try fixture.path("notes.md", .{}), .{}),
    );

    // A staging directory that already existed is emptied rather than
    // removed, so a caller that pre-created it keeps it.
    try Dir.cwd().createDirPath(io, output);
    try expectStageFails(&fixture);
    const entries = try listTree(arena.allocator(), io, output);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "stage refuses a staging directory that is not empty" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var fixture = try Fixture.create(arena.allocator(), io);
    defer fixture.deinit();
    try fixture.makeAll();
    try fixture.write(try fixture.path("staged/leftover", .{}), "x");
    try expectStageFails(&fixture);
    try std.testing.expect(std.mem.startsWith(
        u8,
        fixture.diagnostic.message(),
        "staging directory is not empty: ",
    ));
}

test "verify-candidate refuses a mutated manifest and a swapped asset" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try Fixture.create(allocator, io);
    defer fixture.deinit();
    const entry = contracts.lookup("x86_64-full").?;
    try fixture.makeBundle(entry, .{});
    const manifest = try fixture.path("candidates/{s}/candidate.json", .{entry.key});
    const asset = try fixture.path(
        "candidates/{s}/{s}",
        .{ entry.key, entry.asset_name },
    );

    var verified = try verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        entry.key,
        Fixture.source_commit,
        &fixture.diagnostic,
    );
    try std.testing.expectEqualStrings(
        &digest_support.hexBytes("x86_64-full\n"),
        verified.sha256,
    );
    try std.testing.expectEqual(@as(u64, 12), verified.bytes);
    try std.testing.expectEqual(@as(i64, 1024), verified.virtual_size);
    verified.deinit();

    // The wrong key, the wrong commit, and changed bytes are each refused.
    try std.testing.expectError(error.InvalidKey, verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        "aarch64-core",
        Fixture.source_commit,
        &fixture.diagnostic,
    ));
    try std.testing.expectError(error.IdentityMismatch, verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        entry.key,
        "b" ** 40,
        &fixture.diagnostic,
    ));

    try fixture.write(asset, "tampered\n");
    try std.testing.expectError(error.DigestMismatch, verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        entry.key,
        Fixture.source_commit,
        &fixture.diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "x86_64-full: candidate bytes do not match the bound digest",
        fixture.diagnostic.message(),
    );
}

test "verify-candidate refuses provenance the manifest does not bind" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try Fixture.create(allocator, io);
    defer fixture.deinit();
    const entry = contracts.lookup("aarch64-full").?;
    try fixture.makeBundle(entry, .{});
    const manifest = try fixture.path("candidates/{s}/candidate.json", .{entry.key});
    const asset = try fixture.path(
        "candidates/{s}/{s}",
        .{ entry.key, entry.asset_name },
    );

    // A file that appeared after the manifest was written is not bound.
    try fixture.write(
        try fixture.path(
            "candidates/{s}/internal-provenance/extra.txt",
            .{entry.key},
        ),
        "surprise\n",
    );
    try std.testing.expectError(error.ProvenanceMismatch, verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        entry.key,
        Fixture.source_commit,
        &fixture.diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "aarch64-full: provenance file allowlist mismatch",
        fixture.diagnostic.message(),
    );
}
