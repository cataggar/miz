//! Validates the internal provenance tree a candidate binds.
//!
//! Three separate contracts live here, and all three are re-checked by every
//! job that touches a candidate rather than trusted from the document:
//!
//! * the per-file record list and its aggregate digest, which is what makes
//!   the provenance tree tamper-evident and is also where private key material
//!   is refused;
//! * `ubuntu2604-build-provenance.json`, which binds the immutable Canonical
//!   snapshot, the signed `SHA256SUMS` that names the source image, the
//!   architecture-specific disk layout transform, and the exact debz closure
//!   locks and transaction results;
//! * `uki-signing-<flavor>-<architecture>.json`, which binds the signer
//!   identity, the canonical DER certificate, and the digest chain from the
//!   unsigned UKI to the bytes read back out of the finalized image.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const contracts = @import("contracts.zig");
const disk_geometry = @import("disk_geometry.zig");
const keys = @import("keys.zig");
const runtime_contract = @import("ubuntu2604_runtime_contract");
const runtime_contract_document = @import("runtime_contract_document.zig");
const size_budget = @import("size_budget.zig");
const size_inventory = @import("size_inventory.zig");
const support = @import("support.zig");
const url = @import("url.zig");

const Builder = support.Builder;
const Diagnostic = support.Diagnostic;
const Error = support.Error;
const fail = support.fail;

/// A `{"filename": ..., "sha256": ...}` binding, already checked against the
/// filename its position requires.
pub const Binding = struct {
    filename: []const u8,
    sha256: []const u8,
};

/// `require_file_binding`.
fn requireFileBinding(
    value: ?std.json.Value,
    label: []const u8,
    expected_filename: []const u8,
    diagnostic: *Diagnostic,
) Error!Binding {
    const object = support.objectOf(value) orelse return fail(
        diagnostic,
        "{s} binding is invalid",
        .{label},
    );
    const expected_fields = [_][]const u8{ "filename", "sha256" };
    if (!support.hasExactFields(object, &expected_fields)) return fail(
        diagnostic,
        "{s} binding is invalid",
        .{label},
    );
    if (!support.stringIs(object.get("filename"), expected_filename)) return fail(
        diagnostic,
        "{s} filename is not {s}",
        .{ label, expected_filename },
    );
    var digest_label_buffer: [192]u8 = undefined;
    const digest_label = std.fmt.bufPrint(
        &digest_label_buffer,
        "{s} digest",
        .{label},
    ) catch label;
    const sha256 = try support.requireSha256(
        object.get("sha256"),
        digest_label,
        diagnostic,
    );
    return .{ .filename = expected_filename, .sha256 = sha256 };
}

/// `require_bound_provenance_file`: the named file must exist under the
/// provenance root and hash to the digest the binding claims. Returns the
/// allocated path so the caller can read it.
fn requireBoundProvenanceFile(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    binding: Binding,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error![]u8 {
    const path = try support.joinPath(allocator, &.{ root, binding.filename });
    errdefer allocator.free(path);
    if (!support.isRegularFile(io, path)) return fail(
        diagnostic,
        "{s} file is absent from provenance",
        .{label},
    );
    const hashed = support.hashArtifact(io, path) catch return fail(
        diagnostic,
        "{s} file is absent from provenance",
        .{label},
    );
    if (!std.mem.eql(u8, &hashed.hex, binding.sha256)) return fail(
        diagnostic,
        "{s} file digest does not match provenance",
        .{label},
    );
    return path;
}

/// `provenance_records`: one record per regular file under `root`, in
/// `pathlib` order, with private key material refused before anything is
/// recorded.
pub fn records(
    allocator: Allocator,
    builder: Builder,
    io: Io,
    root: []const u8,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    if (!support.isDirectory(io, root)) return fail(
        diagnostic,
        "provenance directory is missing: {s}",
        .{root},
    );
    const paths = support.listFiles(allocator, io, root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "provenance directory is missing: {s}",
            .{root},
        ),
    };
    defer support.freePaths(allocator, paths);

    var list = builder.array();
    for (paths) |relative| {
        const path = try support.joinPath(allocator, &.{ root, relative });
        defer allocator.free(path);
        const contents = support.file_support.readBounded(
            allocator,
            io,
            path,
            support.artifact_max_bytes,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(
                diagnostic,
                "cannot read {s}: {s}",
                .{ path, @errorName(err) },
            ),
        };
        defer allocator.free(contents);
        if (keys.containsPrivateKey(contents)) return fail(
            diagnostic,
            "private key material is forbidden in provenance: {s}",
            .{path},
        );

        var record = builder.object();
        try builder.putString(&record, "path", relative);
        try builder.putInteger(&record, "bytes", @intCast(contents.len));
        try builder.putString(
            &record,
            "sha256",
            &support.digest.hexBytes(contents),
        );
        try list.append(.{ .object = record });
    }
    if (list.items.len == 0) return fail(
        diagnostic,
        "provenance directory is empty: {s}",
        .{root},
    );
    return .{ .array = list };
}

/// `parse_sha256sums`: every line must be the canonical
/// `<digest> <space><binary marker><basename>` form, with no duplicate names.
const Sums = struct {
    entries: std.StringHashMapUnmanaged([]const u8),
    text: []u8,

    fn deinit(self: *Sums, allocator: Allocator) void {
        self.entries.deinit(allocator);
        allocator.free(self.text);
        self.* = undefined;
    }
};

fn parseSha256sums(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!Sums {
    const text = support.file_support.readBounded(
        allocator,
        io,
        path,
        support.document_max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read Ubuntu SHA256SUMS: {s}",
            .{@errorName(err)},
        ),
    };
    errdefer allocator.free(text);
    if (!std.unicode.utf8ValidateSlice(text)) return fail(
        diagnostic,
        "cannot read Ubuntu SHA256SUMS: {s}",
        .{"InvalidUtf8"},
    );

    var entries: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer entries.deinit(allocator);

    // `str.splitlines()` drops a trailing newline and never yields a final
    // empty line, which is why an ordinary checksum file parses cleanly; a
    // blank line in the middle still becomes an entry, and fails.
    var rest: []const u8 = text;
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const raw = rest[0..end];
        rest = if (end == rest.len) rest[end..] else rest[end + 1 ..];
        const line = if (std.mem.endsWith(u8, raw, "\r"))
            raw[0 .. raw.len - 1]
        else
            raw;
        if (line.len < 67 or !support.isSha256(line[0..64]) or line[64] != ' ') {
            return fail(
                diagnostic,
                "Ubuntu SHA256SUMS contains a noncanonical entry",
                .{},
            );
        }
        if (line[65] != ' ' and line[65] != '*') return fail(
            diagnostic,
            "Ubuntu SHA256SUMS contains a noncanonical entry",
            .{},
        );
        const filename = line[66..];
        for (filename) |byte| {
            if (std.ascii.isWhitespace(byte)) return fail(
                diagnostic,
                "Ubuntu SHA256SUMS contains a noncanonical entry",
                .{},
            );
        }
        if (!std.mem.eql(u8, std.fs.path.basename(filename), filename) or
            entries.contains(filename))
        {
            return fail(
                diagnostic,
                "Ubuntu SHA256SUMS contains an invalid or duplicate filename",
                .{},
            );
        }
        try entries.put(allocator, filename, line[0..64]);
    }
    if (entries.count() == 0) return fail(
        diagnostic,
        "Ubuntu SHA256SUMS is empty",
        .{},
    );
    return .{ .entries = entries, .text = text };
}

/// The size inventory the build bound into its provenance (issue #677 step 1).
///
/// The binding is checked the same way every other provenance file is -- named
/// exactly, hashed, and re-read from the tree rather than trusted from the
/// document -- and the inventory itself is then validated in full. A candidate
/// that carries a measurement nobody can reproduce from its own bundle is not
/// carrying a measurement.
fn validateSizeInventory(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    object: *const std.json.ObjectMap,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    var name_buffer: [96]u8 = undefined;
    const expected_name = std.fmt.bufPrint(
        &name_buffer,
        "ubuntu2604-size-inventory-{s}-{s}.json",
        .{ @tagName(flavor), architecture },
    ) catch return fail(diagnostic, "Ubuntu size inventory binding is invalid", .{});
    const binding = try requireFileBinding(
        object.get("size_inventory"),
        "Ubuntu size inventory",
        expected_name,
        diagnostic,
    );
    const path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        binding,
        "Ubuntu size inventory",
        diagnostic,
    );
    defer allocator.free(path);
    var parsed = try size_inventory.readValidated(allocator, io, path, .{
        .architecture = architecture,
        .flavor = @tagName(flavor),
        // A finished candidate has been built, finalized, and published, so
        // every phase up to publication is expected; first-boot growth is
        // appended later by the stage that boots it.
        .required_phases = &.{ .root_build, .image_build, .publication },
    }, diagnostic);
    parsed.deinit();
}

/// The runtime contract the build bound into its provenance (issue #677 step 2).
///
/// Core is the flavor being minimized, so it is the flavor that carries an
/// explicit statement of what it needs. The binding is checked exactly like
/// every other provenance file -- named, hashed, and re-read from the tree --
/// and the document is then re-validated against the contract this tool was
/// compiled with. A candidate whose contract has drifted from the source that
/// accepted it is a candidate nobody can review.
fn validateRuntimeContract(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    object: *const std.json.ObjectMap,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    var name_buffer: [96]u8 = undefined;
    const expected_name = contracts.runtimeContractFilename(
        &name_buffer,
        flavor,
        architecture,
    ) orelse return fail(diagnostic, "Ubuntu runtime contract binding is invalid", .{});
    const binding = try requireFileBinding(
        object.get("runtime_contract"),
        "Ubuntu runtime contract",
        expected_name,
        diagnostic,
    );
    const path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        binding,
        "Ubuntu runtime contract",
        diagnostic,
    );
    defer allocator.free(path);
    var parsed = runtime_contract_document.readValidated(allocator, io, path, .{
        .architecture = architecture,
        .flavor = @tagName(flavor),
    }, diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Failed => return error.Failed,
    };
    parsed.deinit();
}

/// The calculated core geometry the build bound into its provenance (issue
/// #677 step 5).
///
/// Checked exactly like the size inventory and the runtime contract: named,
/// hashed, re-read from the candidate tree, and then fully re-validated --
/// which for a geometry report means recomputing every offset and length from
/// the document's own measurements and refusing a plan that lands back on the
/// retired inherited size.
///
/// Binding the report to the *artifact's* virtual size is the workflows' job
/// (`disk-geometry-verify --virtual-size`), where the finished asset is on
/// disk to be measured. Doing it here as well would only compare the
/// provenance's own two fields, which the builder writes from one plan.
fn validateDiskGeometry(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    object: *const std.json.ObjectMap,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    var name_buffer: [96]u8 = undefined;
    const expected_name = contracts.diskGeometryFilename(
        &name_buffer,
        flavor,
        architecture,
    ) orelse return fail(diagnostic, "Ubuntu disk-geometry binding is invalid", .{});
    const binding = try requireFileBinding(
        object.get("disk_geometry"),
        "Ubuntu disk geometry",
        expected_name,
        diagnostic,
    );
    const path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        binding,
        "Ubuntu disk geometry",
        diagnostic,
    );
    defer allocator.free(path);
    var parsed = disk_geometry.readValidated(allocator, io, path, .{
        .architecture = architecture,
        .flavor = @tagName(flavor),
    }, diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Failed => return error.Failed,
    };
    parsed.deinit();
}

/// Re-checks the size-budget verdict a fresh root binds (issue #677 step 6).
///
/// The verdict is not read; it is re-derived. `size_budget.readValidated`
/// recomputes the reviewed budget's digest from this tool's own tables,
/// recomputes every limit from its recorded baseline, and recomputes the
/// verdict from the observations, so a candidate carrying a hand-written
/// `"result": "pass"` is refused by an unmodified release tool.
///
/// Requiring a *reviewed* budget rather than a recorded baseline is the
/// publication decision, and it belongs to the release gate rather than here: a
/// core validation run exists partly to produce that baseline.
fn validateSizeBudget(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    object: *const std.json.ObjectMap,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    var name_buffer: [96]u8 = undefined;
    const expected_name = contracts.sizeBudgetFilename(
        &name_buffer,
        flavor,
        architecture,
    ) orelse return fail(diagnostic, "Ubuntu size-budget binding is invalid", .{});
    const binding = try requireFileBinding(
        object.get("size_budget"),
        "Ubuntu size budget",
        expected_name,
        diagnostic,
    );
    const path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        binding,
        "Ubuntu size budget",
        diagnostic,
    );
    defer allocator.free(path);
    var parsed = size_budget.readValidated(allocator, io, path, .{
        .architecture = architecture,
        .flavor = @tagName(flavor),
    }, diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Failed => return error.Failed,
    };
    parsed.deinit();
}

/// `validate_ubuntu_disk_layout`.
fn validateDiskLayout(
    value: ?std.json.Value,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    const layout = support.objectOf(value) orelse return fail(
        diagnostic,
        "Ubuntu disk-layout provenance is invalid",
        .{},
    );
    // #677 step 5: core writes its own GPT, so its disk-layout provenance says
    // what it did rather than describing edits to Canonical's table. The same
    // shape holds for both architectures, because neither inherits anything.
    if (flavor == .core) {
        const expected = [_][]const u8{ "inherits_source_geometry", "source", "transform" };
        if (!support.hasExactFields(layout, &expected) or
            !support.stringIs(layout.get("source"), disk_geometry.provenance_source) or
            !support.stringIs(layout.get("transform"), disk_geometry.provenance_transform) or
            layout.get("inherits_source_geometry") == null or
            layout.get("inherits_source_geometry").? != .bool or
            layout.get("inherits_source_geometry").?.bool)
        {
            return fail(
                diagnostic,
                "Ubuntu core disk-layout provenance does not declare a fresh output GPT",
                .{},
            );
        }
        return;
    }
    if (std.mem.eql(u8, architecture, "x86_64")) {
        const expected = [_][]const u8{ "source", "transform" };
        if (!support.hasExactFields(layout, &expected) or
            !support.stringIs(layout.get("source"), "canonical-gen2-gpt") or
            !support.stringIs(layout.get("transform"), "preserved"))
        {
            return fail(
                diagnostic,
                "Ubuntu x86_64 disk-layout provenance is invalid",
                .{},
            );
        }
        return;
    }
    if (!std.mem.eql(u8, architecture, "aarch64")) return fail(
        diagnostic,
        "unsupported Ubuntu provenance architecture: '{s}'",
        .{architecture},
    );

    const expected = [_][]const u8{
        "esp",
        "retired_xbootldr",
        "source",
        "transform",
    };
    if (!support.hasExactFields(layout, &expected)) return fail(
        diagnostic,
        "Ubuntu Arm64 disk-layout provenance is invalid",
        .{},
    );
    if (!support.stringIs(layout.get("source"), "canonical-gen2-gpt") or
        !support.stringIs(layout.get("transform"), "arm64-esp-rebuild-v1"))
    {
        return fail(
            diagnostic,
            "Ubuntu Arm64 disk-layout provenance is invalid",
            .{},
        );
    }

    const esp_fields = [_][]const u8{
        "content",
        "fat32",
        "first_lba",
        "last_lba",
        "size_bytes",
        "table_index",
    };
    const esp = support.objectOf(layout.get("esp"));
    if (esp == null or
        !support.hasExactFields(esp.?, &esp_fields) or
        support.integerOf(esp.?.get("table_index")) != 14 or
        support.integerOf(esp.?.get("first_lba")) != 2048 or
        support.integerOf(esp.?.get("last_lba")) != 1_050_623 or
        support.integerOf(esp.?.get("size_bytes")) != 512 * 1024 * 1024 or
        !support.stringIs(esp.?.get("fat32"), "reformatted-preserve-volume-id") or
        !support.stringIs(esp.?.get("content"), "signed-fallback-only"))
    {
        return fail(diagnostic, "Ubuntu Arm64 ESP provenance is invalid", .{});
    }

    const retired_fields = [_][]const u8{ "cleared", "table_index" };
    const retired = support.objectOf(layout.get("retired_xbootldr"));
    if (retired == null or
        !support.hasExactFields(retired.?, &retired_fields) or
        support.integerOf(retired.?.get("table_index")) != 12 or
        !support.isTrue(retired.?.get("cleared")))
    {
        return fail(
            diagnostic,
            "Ubuntu Arm64 XBOOTLDR provenance is invalid",
            .{},
        );
    }
}

/// The validated `ubuntu2604-build-provenance.json`. The document is returned
/// so the caller can bind or compare the exact bytes it validated.
pub const UbuntuProvenance = struct {
    document: support.json_document.Document,

    pub fn value(self: *const UbuntuProvenance) std.json.Value {
        return self.document.parsed.value;
    }

    pub fn deinit(self: *UbuntuProvenance) void {
        self.document.deinit();
        self.* = undefined;
    }
};

/// `validate_ubuntu_provenance`.
pub fn validateUbuntu(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    virtual_size: ?i64,
    diagnostic: *Diagnostic,
) Error!UbuntuProvenance {
    const path = try support.joinPath(
        allocator,
        &.{ root, contracts.ubuntu_provenance_filename },
    );
    defer allocator.free(path);
    var document = try support.readObject(allocator, io, path, diagnostic);
    errdefer document.deinit();
    const object = document.object();

    const base_fields = [_][]const u8{
        "architecture",
        "artifacts",
        "canonical_key_fingerprint",
        "debz",
        "disk_layout",
        "release",
        "schema",
        "sha256sums_signature_verified",
        "size_inventory",
        "snapshot",
        "type",
    };
    const core_fields = [_][]const u8{
        "disk_geometry",
        "minimum_root_free_bytes",
        "runtime_contract",
        "size_budget",
        "validated_root_free_bytes",
        "flavor",
        "virtual_size",
    } ++ base_fields;
    const expected_fields: []const []const u8 = switch (flavor) {
        .full => &base_fields,
        .core => &core_fields,
    };
    if (!support.hasExactFields(object.*, expected_fields)) return fail(
        diagnostic,
        "Ubuntu build provenance has unexpected fields",
        .{},
    );
    if (support.integerOf(object.get("schema")) != 1 or
        !support.stringIs(object.get("type"), "miz-ubuntu2604-build-provenance") or
        !support.stringIs(object.get("architecture"), architecture) or
        !support.stringIs(object.get("release"), "26.04"))
    {
        return fail(diagnostic, "invalid Ubuntu build provenance identity", .{});
    }

    if (flavor == .core) {
        const provenance_virtual_size = support.integerOf(object.get("virtual_size"));
        const minimum = support.integerOf(object.get("minimum_root_free_bytes"));
        const validated = support.integerOf(object.get("validated_root_free_bytes"));
        if (!support.stringIs(object.get("flavor"), "core") or
            provenance_virtual_size == null or
            provenance_virtual_size.? <= 0 or
            (virtual_size != null and provenance_virtual_size.? != virtual_size.?) or
            minimum == null or minimum.? <= 0 or
            validated == null or
            validated.? < minimum.? or
            validated.? >= provenance_virtual_size.?)
        {
            return fail(
                diagnostic,
                "Ubuntu core size/free-space provenance is invalid",
                .{},
            );
        }
    }

    const snapshot_fields = [_][]const u8{ "base_url", "id" };
    const snapshot = support.objectOf(object.get("snapshot"));
    if (snapshot == null or !support.hasExactFields(snapshot.?, &snapshot_fields)) {
        return fail(diagnostic, "Ubuntu snapshot binding is invalid", .{});
    }
    const snapshot_id = support.stringOf(snapshot.?.get("id"));
    const base_url = support.stringOf(snapshot.?.get("base_url"));
    if (snapshot_id == null or !isSnapshotId(snapshot_id.?) or base_url == null) {
        return fail(diagnostic, "Ubuntu snapshot identity is not immutable", .{});
    }
    const parsed_url = url.split(base_url.?);
    var expected_path_buffer: [128]u8 = undefined;
    const expected_path = std.fmt.bufPrint(
        &expected_path_buffer,
        "/releases/26.04/{s}/",
        .{snapshot_id.?},
    ) catch return fail(
        diagnostic,
        "Ubuntu snapshot URL is not the exact immutable release URL",
        .{},
    );
    if (!std.mem.eql(u8, parsed_url.scheme, "https") or
        !std.mem.eql(u8, parsed_url.netloc, "cloud-images.ubuntu.com") or
        !std.mem.eql(u8, parsed_url.path, expected_path) or
        parsed_url.query.len != 0 or
        parsed_url.fragment.len != 0)
    {
        return fail(
            diagnostic,
            "Ubuntu snapshot URL is not the exact immutable release URL",
            .{},
        );
    }

    const fingerprint = support.stringOf(object.get("canonical_key_fingerprint"));
    if (fingerprint == null or !support.isCommit(fingerprint.?)) return fail(
        diagnostic,
        "Canonical signing key fingerprint is invalid",
        .{},
    );
    if (!support.isTrue(object.get("sha256sums_signature_verified"))) return fail(
        diagnostic,
        "Ubuntu SHA256SUMS signature was not explicitly verified",
        .{},
    );
    try validateDiskLayout(object.get("disk_layout"), architecture, flavor, diagnostic);
    try validateSizeInventory(allocator, io, root, object, architecture, flavor, diagnostic);
    if (flavor == .core) {
        try validateRuntimeContract(
            allocator,
            io,
            root,
            object,
            architecture,
            flavor,
            diagnostic,
        );
        try validateDiskGeometry(
            allocator,
            io,
            root,
            object,
            architecture,
            flavor,
            diagnostic,
        );
        try validateSizeBudget(
            allocator,
            io,
            root,
            object,
            architecture,
            flavor,
            diagnostic,
        );
    }

    const source_architecture = contracts.sourceArchitecture(architecture).?;
    var prefix_buffer: [64]u8 = undefined;
    const prefix = std.fmt.bufPrint(
        &prefix_buffer,
        "ubuntu-26.04-server-cloudimg-{s}",
        .{source_architecture},
    ) catch unreachable;
    var image_name_buffer: [80]u8 = undefined;
    const source_image_name = std.fmt.bufPrint(
        &image_name_buffer,
        "{s}.img",
        .{prefix},
    ) catch unreachable;
    var manifest_name_buffer: [80]u8 = undefined;
    const image_manifest_name = std.fmt.bufPrint(
        &manifest_name_buffer,
        "{s}.manifest",
        .{prefix},
    ) catch unreachable;

    const artifact_fields = [_][]const u8{
        "image_manifest",
        "sha256sums",
        "sha256sums_signature",
        "source_image",
    };
    const artifacts = support.objectOf(object.get("artifacts"));
    if (artifacts == null or !support.hasExactFields(artifacts.?, &artifact_fields)) {
        return fail(diagnostic, "Ubuntu source artifact bindings are not exact", .{});
    }

    // The core flavor records an additional `role` on the source image. It is
    // validated here and then dropped, so the remaining binding is checked by
    // exactly the same rule as the full flavor.
    var reduced_source_image: std.json.ObjectMap = .empty;
    defer reduced_source_image.deinit(allocator);
    var source_image_value = artifacts.?.get("source_image").?;
    if (flavor == .core) {
        const role_fields = [_][]const u8{ "filename", "role", "sha256" };
        const entry = support.objectOf(source_image_value);
        if (entry == null or
            !support.hasExactFields(entry.?, &role_fields) or
            !support.stringIs(entry.?.get("role"), "signed-gpt-esp-substrate"))
        {
            return fail(diagnostic, "Ubuntu core source-image role is invalid", .{});
        }
        try reduced_source_image.put(
            allocator,
            "filename",
            entry.?.get("filename").?,
        );
        try reduced_source_image.put(allocator, "sha256", entry.?.get("sha256").?);
        source_image_value = .{ .object = reduced_source_image };
    }

    const sha256sums = try requireFileBinding(
        artifacts.?.get("sha256sums"),
        "Ubuntu sha256sums",
        "SHA256SUMS",
        diagnostic,
    );
    const signature = try requireFileBinding(
        artifacts.?.get("sha256sums_signature"),
        "Ubuntu sha256sums_signature",
        "SHA256SUMS.gpg",
        diagnostic,
    );
    const source_image = try requireFileBinding(
        source_image_value,
        "Ubuntu source_image",
        source_image_name,
        diagnostic,
    );
    const image_manifest = try requireFileBinding(
        artifacts.?.get("image_manifest"),
        "Ubuntu image_manifest",
        image_manifest_name,
        diagnostic,
    );

    const checksum_path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        sha256sums,
        "Ubuntu SHA256SUMS",
        diagnostic,
    );
    defer allocator.free(checksum_path);
    allocator.free(try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        signature,
        "Ubuntu SHA256SUMS signature",
        diagnostic,
    ));
    allocator.free(try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        image_manifest,
        "Ubuntu image manifest",
        diagnostic,
    ));

    var sums = try parseSha256sums(allocator, io, checksum_path, diagnostic);
    defer sums.deinit(allocator);
    for ([_]Binding{ source_image, image_manifest }) |binding| {
        const recorded = sums.entries.get(binding.filename);
        if (recorded == null or !std.mem.eql(u8, recorded.?, binding.sha256)) {
            return fail(
                diagnostic,
                "Ubuntu SHA256SUMS does not bind {s}",
                .{binding.filename},
            );
        }
    }

    try validateDebz(
        allocator,
        io,
        root,
        object.get("debz"),
        source_architecture,
        flavor,
        diagnostic,
    );
    return .{ .document = document };
}

/// `SNAPSHOT_ID_RE`: `release-YYYYMMDD` with an optional `.N` respin suffix.
fn isSnapshotId(text: []const u8) bool {
    const prefix = "release-";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    var rest = text[prefix.len..];
    if (rest.len < 8) return false;
    for (rest[0..8]) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    rest = rest[8..];
    if (rest.len == 0) return true;
    if (rest[0] != '.') return false;
    rest = rest[1..];
    if (rest.len == 0) return false;
    for (rest) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn validateDebz(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    value: ?std.json.Value,
    source_architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!void {
    const base_fields = [_][]const u8{ "api_commit", "baseline", "transactions" };
    const core_fields = [_][]const u8{ "build_stage", "kernel_selection", "package_roots" } ++
        base_fields;
    const expected_fields: []const []const u8 = switch (flavor) {
        .full => &base_fields,
        .core => &core_fields,
    };
    const debz = support.objectOf(value);
    if (debz == null or !support.hasExactFields(debz.?, expected_fields)) {
        return fail(diagnostic, "debz provenance binding is invalid", .{});
    }
    if (!support.stringIs(debz.?.get("api_commit"), contracts.debz_api_commit)) {
        return fail(
            diagnostic,
            "debz API commit is not the embedded miz revision",
            .{},
        );
    }

    const expected_baseline_source = switch (flavor) {
        .core => "empty-debz-root",
        .full => "canonical-image-dpkg-status",
    };
    const baseline_fields = [_][]const u8{ "enforcement", "source" };
    const baseline = support.objectOf(debz.?.get("baseline"));
    if (baseline == null or
        !support.hasExactFields(baseline.?, &baseline_fields) or
        !support.stringIs(baseline.?.get("source"), expected_baseline_source) or
        !support.stringIs(baseline.?.get("enforcement"), "exact-final-closure"))
    {
        return fail(diagnostic, "debz baseline provenance contract is invalid", .{});
    }

    // The core roots are not a literal list any more: issue #677 step 4 selects
    // the kernel from a metapackage so security updates keep arriving without a
    // version pinned into this repository. What is exact is the *shape* -- the
    // selected image, its module tree, then the contract's literal guest roots
    // -- and the selection has to agree with the separately bound selector.
    var core_root_names: [contracts.core_package_root_count][]const u8 = undefined;
    var selection: ?runtime_contract.KernelSelection = null;
    if (flavor == .core) {
        const roots = support.arrayOf(debz.?.get("package_roots")) orelse return fail(
            diagnostic,
            "Ubuntu core package roots are not exact or stably ordered",
            .{},
        );
        const resolved = contracts.validateCorePackageRoots(roots) catch return fail(
            diagnostic,
            "Ubuntu core package roots are not exact or stably ordered",
            .{},
        );
        selection = resolved;
        for (roots, 0..) |entry, index| core_root_names[index] = support.stringOf(entry).?;
        try validateKernelSelection(
            debz.?.get("kernel_selection"),
            resolved,
            source_architecture,
            diagnostic,
        );
    }

    const expected_packages: []const []const u8 = switch (flavor) {
        .full => &contracts.full_debz_packages,
        .core => &core_root_names,
    };

    const transactions = support.arrayOf(debz.?.get("transactions"));
    if (transactions == null or transactions.?.len != expected_packages.len) {
        return fail(
            diagnostic,
            "debz transaction set is not exact or stably ordered",
            .{},
        );
    }
    for (transactions.?, expected_packages) |item, package| {
        const entry = support.objectOf(item) orelse return fail(
            diagnostic,
            "debz transaction set is not exact or stably ordered",
            .{},
        );
        if (!support.stringIs(entry.get("package"), package)) return fail(
            diagnostic,
            "debz transaction set is not exact or stably ordered",
            .{},
        );
    }

    for (transactions.?, expected_packages, 0..) |item, package, index| {
        const transaction_baseline: DebzBaseline =
            if (flavor == .core and index == 0) .empty else .retained;
        try validateDebzTransaction(
            allocator,
            io,
            root,
            item,
            package,
            source_architecture,
            transaction_baseline,
            diagnostic,
        );
    }

    if (flavor == .core) try validateBuildStage(
        allocator,
        io,
        root,
        debz.?.get("build_stage"),
        selection.?,
        source_architecture,
        diagnostic,
    );
}

/// The selector binding: which metapackage was resolved, what it selected, and
/// the exact lock that resolution produced.
///
/// This is what keeps "prefer exact versioned kernel packages" from becoming "a
/// version somebody typed once". The selection is only defensible if the lock
/// it came from is published and bound, so the lock is validated here with the
/// same machinery as an installing transaction -- minus the transaction, since
/// nothing was installed.
fn validateKernelSelection(
    value: ?std.json.Value,
    selection: runtime_contract.KernelSelection,
    source_architecture: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const selection_fields = [_][]const u8{
        "exact_lock",
        "image_package",
        "kernel_release",
        "modules_package",
        "selector",
        "version",
    };
    const object = support.objectOf(value);
    if (object == null or !support.hasExactFields(object.?, &selection_fields)) {
        return fail(diagnostic, "Ubuntu core kernel selection binding is invalid", .{});
    }
    if (!support.stringIs(object.?.get("selector"), runtime_contract.kernel_templates.selector) or
        !support.stringIs(object.?.get("kernel_release"), selection.release) or
        !support.stringIs(object.?.get("image_package"), selection.image_package) or
        !support.stringIs(object.?.get("modules_package"), selection.modules_package))
    {
        return fail(
            diagnostic,
            "Ubuntu core kernel selection does not describe the published roots",
            .{},
        );
    }
    const version = support.stringOf(object.?.get("version")) orelse "";
    if (version.len == 0) return fail(
        diagnostic,
        "Ubuntu core kernel selection does not record the selected version",
        .{},
    );

    const lock_fields = [_][]const u8{ "digest_sha256", "filename", "sha256" };
    const exact_lock = support.objectOf(object.?.get("exact_lock"));
    if (exact_lock == null or !support.hasExactFields(exact_lock.?, &lock_fields)) {
        return fail(diagnostic, "Ubuntu core kernel selector lock binding is invalid", .{});
    }
    var name_buffer: [128]u8 = undefined;
    const expected_name = std.fmt.bufPrint(
        &name_buffer,
        "debz-exact-lock-{s}-{s}.json",
        .{ runtime_contract.kernel_templates.selector, source_architecture },
    ) catch unreachable;
    if (!support.stringIs(exact_lock.?.get("filename"), expected_name)) return fail(
        diagnostic,
        "Ubuntu core kernel selector lock binding is invalid",
        .{},
    );
    _ = try support.requireSha256(
        exact_lock.?.get("sha256"),
        "kernel selector lock",
        diagnostic,
    );
    _ = try support.requireSha256(
        exact_lock.?.get("digest_sha256"),
        "kernel selector lock semantic digest",
        diagnostic,
    );
}

/// The initramfs build stage: the roots resolved outside the guest, the
/// transactions that installed them, and the one artifact the stage handed
/// back.
///
/// Issue #677 step 4 is only true if this exists and is bound. A staging root
/// whose output is unattributed is indistinguishable from an initramfs somebody
/// dropped in, which is why the stage publishes the same lock and transaction
/// evidence a guest root does.
fn validateBuildStage(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    value: ?std.json.Value,
    selection: runtime_contract.KernelSelection,
    source_architecture: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const stage_fields = [_][]const u8{
        "initramfs",
        "package_roots",
        "purpose",
        "transactions",
    };
    const stage = support.objectOf(value);
    if (stage == null or !support.hasExactFields(stage.?, &stage_fields)) {
        return fail(diagnostic, "Ubuntu core build stage binding is invalid", .{});
    }
    if (!support.stringIs(stage.?.get("purpose"), "initramfs-generation")) return fail(
        diagnostic,
        "Ubuntu core build stage does not describe initramfs generation",
        .{},
    );
    if (!support.isExactOrderedStrings(
        stage.?.get("package_roots"),
        &contracts.core_build_package_roots,
    )) {
        return fail(
            diagnostic,
            "Ubuntu core build stage roots are not the contract's build tooling",
            .{},
        );
    }

    const initramfs_fields = [_][]const u8{ "bytes", "kernel_release", "path", "sha256" };
    const initramfs = support.objectOf(stage.?.get("initramfs"));
    if (initramfs == null or !support.hasExactFields(initramfs.?, &initramfs_fields)) {
        return fail(diagnostic, "Ubuntu core build stage output binding is invalid", .{});
    }
    var path_buffer: [128]u8 = undefined;
    const expected_path = std.fmt.bufPrint(
        &path_buffer,
        "/boot/initrd.img-{s}",
        .{selection.release},
    ) catch unreachable;
    if (!support.stringIs(initramfs.?.get("path"), expected_path) or
        !support.stringIs(initramfs.?.get("kernel_release"), selection.release))
    {
        return fail(
            diagnostic,
            "Ubuntu core build stage output is not the selected kernel's initramfs",
            .{},
        );
    }
    _ = try support.requireSha256(
        initramfs.?.get("sha256"),
        "build stage initramfs",
        diagnostic,
    );
    const bytes = support.integerOf(initramfs.?.get("bytes")) orelse 0;
    if (bytes <= 0) return fail(
        diagnostic,
        "Ubuntu core build stage initramfs size is invalid",
        .{},
    );

    const transactions = support.arrayOf(stage.?.get("transactions"));
    if (transactions == null or
        transactions.?.len != contracts.core_build_package_roots.len)
    {
        return fail(
            diagnostic,
            "Ubuntu core build stage transaction set is not exact or stably ordered",
            .{},
        );
    }
    for (transactions.?, contracts.core_build_package_roots) |item, package| {
        const entry = support.objectOf(item) orelse return fail(
            diagnostic,
            "Ubuntu core build stage transaction set is not exact or stably ordered",
            .{},
        );
        if (!support.stringIs(entry.get("package"), package)) return fail(
            diagnostic,
            "Ubuntu core build stage transaction set is not exact or stably ordered",
            .{},
        );
        // The stage starts from the finished guest closure, so its baseline is
        // retained rather than empty: an "empty" build stage would mean the
        // initramfs was generated against no kernel at all.
        try validateDebzTransaction(
            allocator,
            io,
            root,
            item,
            package,
            source_architecture,
            .retained,
            diagnostic,
        );
    }
}

const DebzBaseline = enum {
    empty,
    retained,
};

fn validateDebzTransaction(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    value: std.json.Value,
    package: []const u8,
    source_architecture: []const u8,
    baseline: DebzBaseline,
    diagnostic: *Diagnostic,
) Error!void {
    const item_fields = [_][]const u8{
        "exact_lock",
        "package",
        "transaction_provenance",
    };
    const item = support.objectOf(value) orelse return fail(
        diagnostic,
        "{s}: debz transaction binding is invalid",
        .{package},
    );
    if (!support.hasExactFields(item, &item_fields)) return fail(
        diagnostic,
        "{s}: debz transaction binding is invalid",
        .{package},
    );

    const lock_fields = [_][]const u8{ "digest_sha256", "filename", "sha256" };
    const exact_lock = support.objectOf(item.get("exact_lock"));
    if (exact_lock == null or !support.hasExactFields(exact_lock.?, &lock_fields)) {
        return fail(diagnostic, "{s}: debz exact-lock binding is invalid", .{package});
    }

    var lock_name_buffer: [128]u8 = undefined;
    const lock_name = std.fmt.bufPrint(
        &lock_name_buffer,
        "debz-exact-lock-{s}-{s}.json",
        .{ package, source_architecture },
    ) catch return fail(
        diagnostic,
        "{s}: debz exact-lock binding is invalid",
        .{package},
    );
    var lock_label_buffer: [96]u8 = undefined;
    const lock_label = std.fmt.bufPrint(
        &lock_label_buffer,
        "{s} debz exact lock",
        .{package},
    ) catch unreachable;

    var reduced_lock: std.json.ObjectMap = .empty;
    defer reduced_lock.deinit(allocator);
    if (exact_lock.?.get("filename")) |entry| {
        try reduced_lock.put(allocator, "filename", entry);
    }
    if (exact_lock.?.get("sha256")) |entry| {
        try reduced_lock.put(allocator, "sha256", entry);
    }
    const lock_binding = try requireFileBinding(
        .{ .object = reduced_lock },
        lock_label,
        lock_name,
        diagnostic,
    );

    var lock_digest_label_buffer: [128]u8 = undefined;
    const lock_digest_label = std.fmt.bufPrint(
        &lock_digest_label_buffer,
        "{s} debz exact-lock semantic digest",
        .{package},
    ) catch unreachable;
    const lock_digest = try support.requireSha256(
        exact_lock.?.get("digest_sha256"),
        lock_digest_label,
        diagnostic,
    );

    const lock_path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        lock_binding,
        lock_label,
        diagnostic,
    );
    defer allocator.free(lock_path);
    var lock_document = try support.readObject(allocator, io, lock_path, diagnostic);
    defer lock_document.deinit();
    try validateDebzLock(
        lock_document.object(),
        package,
        source_architecture,
        lock_digest,
        baseline,
        diagnostic,
    );

    const transaction_fields = [_][]const u8{
        "digest_sha256",
        "filename",
        "lock_sha256",
        "sha256",
    };
    const transaction = support.objectOf(item.get("transaction_provenance"));
    if (transaction == null or
        !support.hasExactFields(transaction.?, &transaction_fields))
    {
        return fail(
            diagnostic,
            "{s}: debz transaction provenance binding is invalid",
            .{package},
        );
    }

    var provenance_name_buffer: [160]u8 = undefined;
    const provenance_name = std.fmt.bufPrint(
        &provenance_name_buffer,
        "debz-transaction-provenance-{s}-{s}.json",
        .{ package, source_architecture },
    ) catch return fail(
        diagnostic,
        "{s}: debz transaction provenance binding is invalid",
        .{package},
    );
    var provenance_label_buffer: [128]u8 = undefined;
    const provenance_label = std.fmt.bufPrint(
        &provenance_label_buffer,
        "{s} debz transaction provenance",
        .{package},
    ) catch unreachable;

    var reduced_transaction: std.json.ObjectMap = .empty;
    defer reduced_transaction.deinit(allocator);
    if (transaction.?.get("filename")) |entry| {
        try reduced_transaction.put(allocator, "filename", entry);
    }
    if (transaction.?.get("sha256")) |entry| {
        try reduced_transaction.put(allocator, "sha256", entry);
    }
    const transaction_binding = try requireFileBinding(
        .{ .object = reduced_transaction },
        provenance_label,
        provenance_name,
        diagnostic,
    );

    var transaction_digest_label_buffer: [160]u8 = undefined;
    const transaction_digest_label = std.fmt.bufPrint(
        &transaction_digest_label_buffer,
        "{s} debz transaction provenance semantic digest",
        .{package},
    ) catch unreachable;
    const transaction_digest = try support.requireSha256(
        transaction.?.get("digest_sha256"),
        transaction_digest_label,
        diagnostic,
    );
    var lock_reference_label_buffer: [160]u8 = undefined;
    const lock_reference_label = std.fmt.bufPrint(
        &lock_reference_label_buffer,
        "{s} debz transaction provenance lock digest",
        .{package},
    ) catch unreachable;
    const transaction_lock = try support.requireSha256(
        transaction.?.get("lock_sha256"),
        lock_reference_label,
        diagnostic,
    );
    if (!std.mem.eql(u8, transaction_lock, lock_digest)) return fail(
        diagnostic,
        "{s}: debz transaction provenance is not bound to the exact lock",
        .{package},
    );

    const transaction_path = try requireBoundProvenanceFile(
        allocator,
        io,
        root,
        transaction_binding,
        provenance_label,
        diagnostic,
    );
    defer allocator.free(transaction_path);
    var transaction_document = try support.readObject(
        allocator,
        io,
        transaction_path,
        diagnostic,
    );
    defer transaction_document.deinit();

    const document = transaction_document.object();
    const final_verification = support.objectOf(document.get("final_verification"));
    if (!support.stringIs(
        document.get("schema"),
        "https://debz.dev/schema/transaction-result-v1",
    ) or
        support.integerOf(document.get("version")) != 1 or
        !support.stringIs(document.get("target_architecture"), source_architecture) or
        !support.stringIs(document.get("lock_sha256"), lock_digest) or
        !support.stringIs(document.get("digest_sha256"), transaction_digest) or
        !support.stringIs(document.get("outcome"), "succeeded") or
        final_verification == null or
        !support.stringIs(final_verification.?.get("status"), "exact_match"))
    {
        return fail(
            diagnostic,
            "{s}: debz transaction provenance does not prove an exact transaction",
            .{package},
        );
    }
}

fn validateDebzLock(
    document: *const std.json.ObjectMap,
    package: []const u8,
    source_architecture: []const u8,
    lock_digest: []const u8,
    baseline: DebzBaseline,
    diagnostic: *Diagnostic,
) Error!void {
    const packages = support.arrayOf(document.get("packages"));
    const repositories = support.arrayOf(document.get("repositories"));
    var retained = false;
    var named = false;
    if (packages) |items| {
        for (items) |entry| {
            const record = support.objectOf(entry) orelse continue;
            const name = support.stringOf(record.get("name"));
            if (name != null and std.mem.eql(u8, name.?, package)) named = true;
            if (!support.stringIs(record.get("retention"), "retained")) continue;
            if (name == null or name.?.len == 0) continue;
            const version = support.stringOf(record.get("version"));
            if (version == null or version.?.len == 0) continue;
            const architecture = support.stringOf(record.get("architecture"));
            if (architecture == null) continue;
            if (!std.mem.eql(u8, architecture.?, source_architecture) and
                !std.mem.eql(u8, architecture.?, "all")) continue;
            retained = true;
        }
    }
    const baseline_valid = switch (baseline) {
        .empty => !retained,
        .retained => retained,
    };
    if (!support.stringIs(
        document.get("schema"),
        "https://debz.dev/schema/exact-closure-lock-v1",
    ) or
        support.integerOf(document.get("version")) != 1 or
        !support.stringIs(document.get("target_architecture"), source_architecture) or
        !support.stringIs(document.get("digest_sha256"), lock_digest) or
        repositories == null or repositories.?.len == 0 or
        packages == null or
        !baseline_valid or
        !named)
    {
        return fail(
            diagnostic,
            "{s}: debz exact lock does not satisfy the Ubuntu release contract",
            .{package},
        );
    }
}

/// The validated UKI signing binding: the canonical value a candidate records
/// under `uki_signing`, plus the fields later jobs read out of it.
pub const Signing = struct {
    value: std.json.Value,
    certificate_sha256: []const u8,
    certificate_der_base64: []const u8,
    fallback_uki_sha256: []const u8,
    signing_certificate_sha256: []const u8,
};

/// `ARTIFACT_SIGNING_ENDPOINT_RE`.
fn isArtifactSigningEndpoint(text: []const u8) bool {
    const prefix = "https://";
    const suffix = ".codesigning.azure.net";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    if (!std.mem.endsWith(u8, text, suffix)) return false;
    const host = text[prefix.len .. text.len - suffix.len];
    if (host.len == 0) return false;
    for (host) |byte| switch (byte) {
        'a'...'z', '0'...'9', '.', '-' => {},
        else => return false,
    };
    return true;
}

/// `ARTIFACT_SIGNING_RESOURCE_RE`.
fn isArtifactSigningResource(text: []const u8) bool {
    if (text.len == 0 or text.len > 128) return false;
    for (text) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// `UUID_RE`.
fn isUuid(text: []const u8) bool {
    const groups = [_]usize{ 8, 4, 4, 4, 12 };
    var rest = text;
    for (groups, 0..) |length, index| {
        if (index > 0) {
            if (rest.len == 0 or rest[0] != '-') return false;
            rest = rest[1..];
        }
        if (rest.len < length) return false;
        for (rest[0..length]) |byte| {
            if (!std.ascii.isHex(byte)) return false;
        }
        rest = rest[length..];
    }
    return rest.len == 0;
}

/// Strict, canonical base64 with padding, matching
/// `base64.b64decode(value, validate=True)`.
pub fn decodeBase64(allocator: Allocator, text: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const length = try decoder.calcSizeForSlice(text);
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    try decoder.decode(bytes, text);
    return bytes;
}

/// `validate_signing_provenance`.
pub fn validateSigning(
    allocator: Allocator,
    builder: Builder,
    io: Io,
    root: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    diagnostic: *Diagnostic,
) Error!Signing {
    const filename = try std.fmt.allocPrint(
        allocator,
        "uki-signing-{s}-{s}.json",
        .{ @tagName(flavor), architecture },
    );
    defer allocator.free(filename);
    const path = try support.joinPath(allocator, &.{ root, filename });
    defer allocator.free(path);

    var document = try support.readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const object = document.object();

    if (support.integerOf(object.get("schema")) != 1 or
        !support.stringIs(object.get("type"), "miz-uki-signing"))
    {
        return fail(diagnostic, "invalid UKI signing provenance schema", .{});
    }
    if (!support.stringIs(object.get("architecture"), architecture) or
        !support.stringIs(object.get("flavor"), @tagName(flavor)))
    {
        return fail(
            diagnostic,
            "UKI signing provenance architecture/flavor mismatch",
            .{},
        );
    }
    if (!support.stringIs(object.get("signer_mode"), "external-command")) {
        return fail(
            diagnostic,
            "release UKIs were not signed by the external provider",
            .{},
        );
    }
    const certificate_sha256 = try support.requireSha256(
        object.get("certificate_sha256"),
        "UKI signing certificate fingerprint",
        diagnostic,
    );
    const certificate_der_base64 = support.stringOf(
        object.get("certificate_der_base64"),
    ) orelse return fail(
        diagnostic,
        "canonical DER UKI signing certificate is absent",
        .{},
    );
    const certificate_der = decodeBase64(allocator, certificate_der_base64) catch
        return fail(
            diagnostic,
            "canonical DER UKI signing certificate is not valid base64",
            .{},
        );
    defer allocator.free(certificate_der);
    if (certificate_der.len == 0 or
        !std.mem.eql(
            u8,
            &support.digest.hexBytes(certificate_der),
            certificate_sha256,
        ))
    {
        return fail(
            diagnostic,
            "canonical DER UKI signing certificate fingerprint mismatch",
            .{},
        );
    }
    if (!support.stringIs(object.get("signature_verification"), "success")) {
        return fail(
            diagnostic,
            "UKI signature verification did not explicitly succeed",
            .{},
        );
    }
    const details = support.stringOf(object.get("certificate_details"));
    if (details == null or details.?.len == 0) return fail(
        diagnostic,
        "UKI signing certificate details are absent",
        .{},
    );

    const provider_fields = [_][]const u8{
        "account",
        "endpoint",
        "name",
        "profile",
        "signing_certificate_sha256",
    };
    const provider = support.objectOf(object.get("provider"));
    if (provider == null or !support.hasExactFields(provider.?, &provider_fields)) {
        return fail(diagnostic, "Artifact Signing provider identity is absent", .{});
    }
    if (!support.stringIs(provider.?.get("name"), "azure-artifact-signing")) {
        return fail(diagnostic, "unexpected UKI signing provider", .{});
    }
    const endpoint = support.stringOf(provider.?.get("endpoint"));
    const account = support.stringOf(provider.?.get("account"));
    const profile = support.stringOf(provider.?.get("profile"));
    if (endpoint == null or !isArtifactSigningEndpoint(endpoint.?) or
        account == null or !isArtifactSigningResource(account.?) or
        profile == null or !isArtifactSigningResource(profile.?))
    {
        return fail(diagnostic, "invalid Artifact Signing provider identity", .{});
    }
    const signing_certificate_sha256 = try support.requireSha256(
        provider.?.get("signing_certificate_sha256"),
        "Artifact Signing leaf certificate fingerprint",
        diagnostic,
    );

    const files = support.arrayOf(object.get("files"));
    if (files == null or files.?.len != 1) return fail(
        diagnostic,
        "UKI signing provenance file bindings are absent",
        .{},
    );
    const fallback_path = if (std.mem.eql(u8, architecture, "x86_64"))
        "EFI/BOOT/BOOTX64.EFI"
    else
        "EFI/BOOT/BOOTAA64.EFI";

    // Only the fallback path is ever loaded: firmware boots one binary, and a
    // generalized image comes up on fresh NVRAM, so it takes the
    // removable-media path. What binds the shipped bytes to the signer is the
    // per-record digest chain below, and the builder's own check that the UKI
    // read back out of the finalized image is the signed artifact.
    var fallback_digest: ?[]const u8 = null;
    for (files.?) |entry| {
        const record = support.objectOf(entry) orelse return fail(
            diagnostic,
            "invalid UKI signing file record",
            .{},
        );
        const uki_path = support.stringOf(record.get("path"));
        if (uki_path == null or !std.mem.eql(u8, uki_path.?, fallback_path)) {
            if (uki_path) |text| return fail(
                diagnostic,
                "unexpected UKI signing path: '{s}'",
                .{text},
            );
            return fail(diagnostic, "unexpected UKI signing path: None", .{});
        }
        var label_buffer: [160]u8 = undefined;
        const unsigned = try support.requireSha256(
            record.get("unsigned_sha256"),
            std.fmt.bufPrint(
                &label_buffer,
                "{s} unsigned UKI digest",
                .{uki_path.?},
            ) catch unreachable,
            diagnostic,
        );
        var signed_label_buffer: [160]u8 = undefined;
        const signed = try support.requireSha256(
            record.get("signed_sha256"),
            std.fmt.bufPrint(
                &signed_label_buffer,
                "{s} signed UKI digest",
                .{uki_path.?},
            ) catch unreachable,
            diagnostic,
        );
        var finalized_label_buffer: [160]u8 = undefined;
        const finalized = try support.requireSha256(
            record.get("finalized_sha256"),
            std.fmt.bufPrint(
                &finalized_label_buffer,
                "{s} finalized UKI digest",
                .{uki_path.?},
            ) catch unreachable,
            diagnostic,
        );
        if (std.mem.eql(u8, unsigned, signed) or !std.mem.eql(u8, signed, finalized)) {
            return fail(
                diagnostic,
                "{s}: invalid signed/finalized UKI digest binding",
                .{uki_path.?},
            );
        }
        const signed_bytes = support.integerOf(record.get("signed_bytes"));
        if (signed_bytes == null or signed_bytes.? <= 0) return fail(
            diagnostic,
            "{s}: invalid signed UKI size",
            .{uki_path.?},
        );
        const operation_id = support.stringOf(record.get("signing_operation_id"));
        if (operation_id == null or !isUuid(operation_id.?)) return fail(
            diagnostic,
            "{s}: invalid Artifact Signing operation ID",
            .{uki_path.?},
        );
        if (!support.stringIs(
            record.get("signing_certificate_sha256"),
            signing_certificate_sha256,
        )) {
            return fail(
                diagnostic,
                "{s}: Artifact Signing leaf fingerprint mismatch",
                .{uki_path.?},
            );
        }
        fallback_digest = signed;
    }
    const signed_fallback = fallback_digest orelse return fail(
        diagnostic,
        "fallback UKI signing record is absent",
        .{},
    );

    var provider_value = builder.object();
    try builder.putString(&provider_value, "name", "azure-artifact-signing");
    try builder.putString(&provider_value, "endpoint", endpoint.?);
    try builder.putString(&provider_value, "account", account.?);
    try builder.putString(&provider_value, "profile", profile.?);

    var value = builder.object();
    try builder.putString(&value, "certificate_sha256", certificate_sha256);
    try builder.putString(
        &value,
        "certificate_der_base64",
        certificate_der_base64,
    );
    try builder.putString(&value, "fallback_uki_sha256", signed_fallback);
    try builder.put(&value, "provider", .{ .object = provider_value });
    try builder.putString(
        &value,
        "signing_certificate_sha256",
        signing_certificate_sha256,
    );
    try builder.putString(&value, "signer_mode", "external-command");
    try builder.putString(&value, "provenance_path", filename);

    return .{
        .value = .{ .object = value },
        .certificate_sha256 = value.get("certificate_sha256").?.string,
        .certificate_der_base64 = value.get("certificate_der_base64").?.string,
        .fallback_uki_sha256 = value.get("fallback_uki_sha256").?.string,
        .signing_certificate_sha256 = value.get("signing_certificate_sha256").?.string,
    };
}

test "debz lock retention matches the declared installed baseline" {
    const empty_lock =
        \\{"schema":"https://debz.dev/schema/exact-closure-lock-v1","version":1,
        \\"target_architecture":"amd64","repositories":[{"fixture":true}],
        \\"packages":[{"name":"linux-azure","version":"1","architecture":"amd64",
        \\"retention":"requested"}],
        \\"digest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    ;
    var empty = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        empty_lock,
        .{},
    );
    defer empty.deinit();
    var diagnostic: Diagnostic = .{};
    try validateDebzLock(
        &empty.value.object,
        "linux-azure",
        "amd64",
        "a" ** 64,
        .empty,
        &diagnostic,
    );
    diagnostic = .{};
    try std.testing.expectError(error.Failed, validateDebzLock(
        &empty.value.object,
        "linux-azure",
        "amd64",
        "a" ** 64,
        .retained,
        &diagnostic,
    ));

    const retained_lock =
        \\{"schema":"https://debz.dev/schema/exact-closure-lock-v1","version":1,
        \\"target_architecture":"amd64","repositories":[{"fixture":true}],
        \\"packages":[{"name":"base-files","version":"1","architecture":"amd64",
        \\"retention":"retained"},{"name":"linux-azure","version":"1","architecture":"amd64",
        \\"retention":"requested"}],
        \\"digest_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    ;
    var retained = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        retained_lock,
        .{},
    );
    defer retained.deinit();
    diagnostic = .{};
    try validateDebzLock(
        &retained.value.object,
        "linux-azure",
        "amd64",
        "b" ** 64,
        .retained,
        &diagnostic,
    );
    diagnostic = .{};
    try std.testing.expectError(error.Failed, validateDebzLock(
        &retained.value.object,
        "linux-azure",
        "amd64",
        "b" ** 64,
        .empty,
        &diagnostic,
    ));
}

test "snapshot identifiers accept only the immutable release spellings" {
    try std.testing.expect(isSnapshotId("release-20260101"));
    try std.testing.expect(isSnapshotId("release-20260101.1"));
    try std.testing.expect(!isSnapshotId("release-2026010"));
    try std.testing.expect(!isSnapshotId("release-20260101."));
    try std.testing.expect(!isSnapshotId("daily-20260101"));
    try std.testing.expect(!isSnapshotId("release-20260101.x"));
    try std.testing.expect(!isSnapshotId(""));
}

test "Artifact Signing identity patterns reject non-canonical spellings" {
    try std.testing.expect(isArtifactSigningEndpoint(
        "https://eus.codesigning.azure.net",
    ));
    try std.testing.expect(!isArtifactSigningEndpoint(
        "http://eus.codesigning.azure.net",
    ));
    try std.testing.expect(!isArtifactSigningEndpoint(
        "https://EUS.codesigning.azure.net",
    ));
    try std.testing.expect(!isArtifactSigningEndpoint(
        "https://eus.codesigning.azure.net/",
    ));
    try std.testing.expect(!isArtifactSigningEndpoint("https://.codesigning.azure.net"));

    try std.testing.expect(isArtifactSigningResource("miz-signing_1.0"));
    try std.testing.expect(!isArtifactSigningResource(""));
    try std.testing.expect(!isArtifactSigningResource("has space"));
    try std.testing.expect(!isArtifactSigningResource("a" ** 129));
}

test "operation identifiers must be UUIDs" {
    try std.testing.expect(isUuid("00000000-0000-4000-8000-000000000001"));
    try std.testing.expect(isUuid("00000000-0000-4000-8000-00000000000A"));
    try std.testing.expect(!isUuid("00000000-0000-4000-8000-00000000001"));
    try std.testing.expect(!isUuid("00000000000040008000000000000001"));
    try std.testing.expect(!isUuid("zzzzzzzz-0000-4000-8000-000000000001"));
}

test "base64 decoding is strict about padding and alphabet" {
    const bytes = try decodeBase64(std.testing.allocator, "bWl6");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("miz", bytes);
    try std.testing.expectError(
        error.InvalidPadding,
        decodeBase64(std.testing.allocator, "bWl"),
    );
    try std.testing.expectError(
        error.InvalidCharacter,
        decodeBase64(std.testing.allocator, "b@l6"),
    );
}
