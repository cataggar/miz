//! The domain checks the Ubuntu workflows and shell harnesses used to embed.
//!
//! Every command here replaces an inline Python block in
//! `.github/workflows/ubuntu2604-release.yml`,
//! `.github/workflows/ubuntu2604-core-validation.yml`,
//! `scripts/ubuntu2604_azure_acceptance.sh`, `scripts/ubuntu2604_publish.sh`,
//! or `scripts/ubuntu2604_local_e2e.sh`. They are all the same kind of thing:
//! a judgement about a document -- the image the build produced, the settings
//! Azure returned, the assets a release actually carries -- and they were only
//! written in shell because the shell was where the document happened to be.
//!
//! Two rules hold throughout. A query that fails is never turned into a
//! success-shaped default, and every check re-reads the file it judges rather
//! than trusting a value passed alongside it.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const Writer = std.Io.Writer;
const contracts = @import("contracts.zig");
const disk_geometry = @import("disk_geometry.zig");
const documents = @import("documents.zig");
const download = @import("download.zig");
const provenance = @import("provenance.zig");
const runtime_contract = @import("ubuntu2604_runtime_contract");
const runtime_contract_document = @import("runtime_contract_document.zig");
const size_inventory = @import("size_inventory.zig");
const support = @import("support.zig");

const Builder = support.Builder;
const Diagnostic = support.Diagnostic;
const Error = support.Error;
/// Commands that report on standard output can also fail to write it.
const OutError = Error || Writer.Error;
const fail = support.fail;

pub const Request = struct {
    command: []const u8,
    argv: []const []const u8,
    diagnostic: *Diagnostic,
};

/// Bound on a downloaded boot diagnostic. Serial logs and screenshots are
/// evidence, not artifacts; anything larger is a sign the URL is not what it
/// claimed to be.
pub const boot_artifact_max_bytes: u64 = 16 * 1024 * 1024;

const cli = @import("cli.zig");

const parse = cli.parse;

/// Reads any JSON document, not only an object: several GitHub API responses
/// this checks are arrays.
fn readValue(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!std.json.Parsed(std.json.Value) {
    const bytes = support.file_support.readBounded(
        allocator,
        io,
        path,
        support.document_max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer allocator.free(bytes);
    return std.json.parseFromSlice(
        std.json.Value,
        allocator,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
}

/// Python truthiness for a JSON value, which is what `if info.get(...)` and
/// `... or {}` mean in the blocks this replaces.
fn isTruthy(value: ?std.json.Value) bool {
    const present = value orelse return false;
    return switch (present) {
        .null => false,
        .bool => |flag| flag,
        .integer => |number| number != 0,
        .float => |number| number != 0,
        .number_string => |text| text.len != 0,
        .string => |text| text.len != 0,
        .array => |items| items.items.len != 0,
        .object => |map| map.count() != 0,
    };
}

fn nestedObject(
    value: ?std.json.Value,
    path: []const []const u8,
) ?std.json.ObjectMap {
    var current = support.objectOf(value) orelse return null;
    for (path) |key| {
        current = support.objectOf(current.get(key)) orelse return null;
    }
    return current;
}

pub fn dispatch(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    request: Request,
) !void {
    const command = request.command;
    const argv = request.argv;
    const diagnostic = request.diagnostic;

    if (std.mem.eql(u8, command, "verify-image-info")) {
        var options = try parse(allocator, argv, &.{
            "--info",
            "--virtual-size",
            "--virtual-size-label",
        });
        defer options.deinit();
        return verifyImageInfo(
            allocator,
            io,
            try options.require("--info"),
            try options.requireInteger("--virtual-size"),
            options.get("--virtual-size-label"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "size-inventory-verify")) {
        var options = try parse(allocator, argv, &.{
            "--report",
            "--architecture",
            "--flavor",
            "--require-phase",
            "--max-unexpected-unowned",
        });
        defer options.deinit();
        return sizeInventoryVerify(
            allocator,
            io,
            out,
            try options.require("--report"),
            options.get("--architecture"),
            options.get("--flavor"),
            options.get("--require-phase"),
            options.get("--max-unexpected-unowned"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "disk-geometry-verify")) {
        var options = try parse(allocator, argv, &.{
            "--geometry",
            "--architecture",
            "--flavor",
            "--virtual-size",
            "--github-env",
        });
        defer options.deinit();
        return diskGeometryVerify(
            allocator,
            io,
            out,
            try options.require("--geometry"),
            options.get("--architecture"),
            options.get("--flavor"),
            options.get("--virtual-size"),
            options.get("--github-env"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "size-inventory-compare")) {
        var options = try parse(allocator, argv, &.{
            "--baseline",
            "--candidate",
            "--output",
            "--step-summary",
        });
        defer options.deinit();
        return sizeInventoryCompare(
            allocator,
            io,
            out,
            try options.require("--baseline"),
            try options.require("--candidate"),
            options.get("--output"),
            options.get("--step-summary"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "runtime-contract-verify")) {
        var options = try parse(allocator, argv, &.{
            "--contract",
            "--architecture",
            "--flavor",
        });
        defer options.deinit();
        return runtimeContractVerify(
            allocator,
            io,
            out,
            try options.require("--contract"),
            options.get("--architecture"),
            options.get("--flavor"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "build-runtime-split-verify")) {
        var options = try parse(allocator, argv, &.{"--provenance"});
        defer options.deinit();
        return buildRuntimeSplitVerify(
            allocator,
            io,
            out,
            try options.require("--provenance"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "runtime-contract-probe-verify")) {
        var options = try parse(allocator, argv, &.{"--report"});
        defer options.deinit();
        return runtimeContractProbeVerify(
            allocator,
            io,
            out,
            try options.require("--report"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "runtime-contract-requirement")) {
        var options = try parse(allocator, argv, &.{ "--report", "--id" });
        defer options.deinit();
        return runtimeContractRequirement(
            allocator,
            io,
            out,
            try options.require("--report"),
            try options.require("--id"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "candidate-signing-env")) {
        var options = try parse(allocator, argv, &.{
            "--manifest",
            "--certificate",
            "--github-env",
        });
        defer options.deinit();
        return candidateSigningEnv(
            allocator,
            io,
            out,
            try options.require("--manifest"),
            try options.require("--certificate"),
            options.get("--github-env"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "resolve-artifacts")) {
        var options = try parse(allocator, argv, &.{
            "--jobs",
            "--artifacts",
            "--kind",
            "--run-id",
            "--source-commit",
            "--max-attempt",
            "--output",
        });
        defer options.deinit();
        return resolveArtifacts(allocator, io, .{
            .jobs = try options.require("--jobs"),
            .artifacts = try options.require("--artifacts"),
            .kind = ArtifactKind.parse(try options.require("--kind")) orelse
                return error.Usage,
            .run_id = try options.require("--run-id"),
            .source_commit = try options.require("--source-commit"),
            .max_attempt = try options.requireInteger("--max-attempt"),
            .output = try options.require("--output"),
        }, diagnostic);
    }
    if (std.mem.eql(u8, command, "release-gate")) {
        var options = try parse(allocator, argv, &.{
            "--candidates",
            "--native-results",
            "--azure-results",
            "--candidate-selection",
            "--native-selection",
            "--azure-selection",
            "--source-commit",
            "--candidate-run-id",
            "--run-id",
        });
        defer options.deinit();
        return releaseGate(allocator, io, .{
            .candidates = try options.require("--candidates"),
            .native_results = try options.require("--native-results"),
            .azure_results = try options.require("--azure-results"),
            .candidate_selection = try options.require("--candidate-selection"),
            .native_selection = try options.require("--native-selection"),
            .azure_selection = try options.require("--azure-selection"),
            .source_commit = try options.require("--source-commit"),
            .candidate_run_id = try options.require("--candidate-run-id"),
            .run_id = try options.require("--run-id"),
        }, diagnostic);
    }
    if (std.mem.eql(u8, command, "core-gate")) {
        var options = try parse(allocator, argv, &.{
            "--candidates",
            "--native-results",
            "--azure-results",
            "--output",
            "--source-commit",
            "--candidate-run-id",
            "--candidate-run-attempt",
            "--run-id",
            "--run-attempt",
        });
        defer options.deinit();
        return coreGate(allocator, io, .{
            .candidates = try options.require("--candidates"),
            .native_results = try options.require("--native-results"),
            .azure_results = try options.require("--azure-results"),
            .output = try options.require("--output"),
            .source_commit = try options.require("--source-commit"),
            .candidate_run_id = try options.require("--candidate-run-id"),
            .candidate_run_attempt = try options.require("--candidate-run-attempt"),
            .run_id = try options.require("--run-id"),
            .run_attempt = try options.require("--run-attempt"),
        }, diagnostic);
    }
    if (std.mem.eql(u8, command, "kvm-api-version")) {
        var options = try parse(allocator, argv, &.{"--device"});
        defer options.deinit();
        return kvmApiVersion(io, options.get("--device") orelse "/dev/kvm", diagnostic);
    }
    if (std.mem.eql(u8, command, "azure-cleanup-tags")) {
        var options = try parse(allocator, argv, &.{
            "--metadata",
            "--run-id",
            "--run-attempt",
            "--candidate-key",
        });
        defer options.deinit();
        return azureCleanupTags(
            allocator,
            io,
            try options.require("--metadata"),
            try options.require("--run-id"),
            try options.require("--run-attempt"),
            try options.require("--candidate-key"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "azure-disk-access")) {
        var options = try parse(allocator, argv, &.{"--response"});
        defer options.deinit();
        var parsed = try readValue(
            allocator,
            io,
            try options.require("--response"),
            diagnostic,
        );
        defer parsed.deinit();
        const object = support.objectOf(parsed.value) orelse return fail(
            diagnostic,
            "Azure disk access response is not a JSON object",
            .{},
        );
        const sas = support.stringOf(object.get("accessSAS")) orelse
            support.stringOf(object.get("accessSas")) orelse "";
        try out.print("{s}\n", .{sas});
        return;
    }
    if (std.mem.eql(u8, command, "azure-boot-artifact")) {
        var options = try parse(allocator, argv, &.{ "--uri", "--output" });
        defer options.deinit();
        const destination = try options.require("--output");
        Dir.cwd().deleteFile(io, destination) catch {};
        download.fetch(
            allocator,
            io,
            try options.require("--uri"),
            destination,
            .{ .max_bytes = boot_artifact_max_bytes },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ResponseTooLarge => {
                Dir.cwd().deleteFile(io, destination) catch {};
                return fail(
                    diagnostic,
                    "boot diagnostic artifact exceeds the size limit",
                    .{},
                );
            },
            else => {
                Dir.cwd().deleteFile(io, destination) catch {};
                return fail(
                    diagnostic,
                    "boot diagnostic artifact download failed",
                    .{},
                );
            },
        };
        return;
    }
    if (std.mem.eql(u8, command, "azure-failure-diagnostics")) {
        var options = try parse(allocator, argv, &.{
            "--output",
            "--instance-view",
            "--serial-console-log",
            "--console-screenshot",
        });
        defer options.deinit();
        var arena: std.heap.ArenaAllocator = .init(allocator);
        defer arena.deinit();
        const builder = Builder.init(arena.allocator());
        var document = builder.object();
        try builder.putInteger(&document, "schema", 1);
        try builder.putString(
            &document,
            "instance_view",
            try options.require("--instance-view"),
        );
        try builder.putString(
            &document,
            "serial_console_log",
            try options.require("--serial-console-log"),
        );
        try builder.putString(
            &document,
            "console_screenshot",
            try options.require("--console-screenshot"),
        );
        return support.writeDocument(
            allocator,
            io,
            try options.require("--output"),
            .{ .object = document },
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "azure-sku")) {
        var options = try parse(allocator, argv, &.{
            "--sku",
            "--vm-size",
            "--architecture",
        });
        defer options.deinit();
        return azureSku(
            allocator,
            io,
            out,
            try options.require("--sku"),
            try options.require("--vm-size"),
            try options.require("--architecture"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "azure-conversion-attestation")) {
        var options = try parse(allocator, argv, &.{
            "--output",
            "--key",
            "--asset-name",
            "--qcow-sha256",
            "--qcow-bytes",
            "--virtual-size",
            "--vhd-sha256",
            "--vhd-bytes",
            "--vhd-current-size",
            "--info",
        });
        defer options.deinit();
        return conversionAttestation(allocator, io, .{
            .output = try options.require("--output"),
            .key = try options.require("--key"),
            .asset_name = try options.require("--asset-name"),
            .qcow_sha256 = try options.require("--qcow-sha256"),
            .qcow_bytes = try options.requireInteger("--qcow-bytes"),
            .virtual_size = try options.requireInteger("--virtual-size"),
            .vhd_sha256 = try options.require("--vhd-sha256"),
            .vhd_bytes = try options.requireInteger("--vhd-bytes"),
            .vhd_current_size = try options.requireInteger("--vhd-current-size"),
            .info = try options.require("--info"),
        }, diagnostic);
    }
    if (std.mem.eql(u8, command, "azure-gallery-request")) {
        var options = try parse(allocator, argv, &.{
            "--output",
            "--location",
            "--disk-id",
            "--certificate",
        });
        defer options.deinit();
        return galleryRequest(
            allocator,
            io,
            try options.require("--output"),
            try options.require("--location"),
            try options.require("--disk-id"),
            try options.require("--certificate"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "azure-gallery-accepted")) {
        var options = try parse(allocator, argv, &.{ "--request", "--response" });
        defer options.deinit();
        var request_document = try support.readObject(
            allocator,
            io,
            try options.require("--request"),
            diagnostic,
        );
        defer request_document.deinit();
        var response_document = try support.readObject(
            allocator,
            io,
            try options.require("--response"),
            diagnostic,
        );
        defer response_document.deinit();
        const expected = requestUefiSettings(
            request_document.object(),
            diagnostic,
        ) catch |err| return err;
        const actual = documents.galleryUefiSettings(response_document.object());
        if (actual == null or !support.jsonEqual(actual.?, expected)) return fail(
            diagnostic,
            "Azure did not accept the exact custom UEFI settings",
            .{},
        );
        return;
    }
    if (std.mem.eql(u8, command, "azure-gallery-state")) {
        var options = try parse(allocator, argv, &.{"--response"});
        defer options.deinit();
        var document = try support.readObject(
            allocator,
            io,
            try options.require("--response"),
            diagnostic,
        );
        defer document.deinit();
        const properties = nestedObject(
            .{ .object = document.object().* },
            &.{"properties"},
        );
        const state = if (properties) |object|
            support.stringOf(object.get("provisioningState")) orelse ""
        else
            "";
        try out.print("{s}\n", .{state});
        return;
    }
    if (std.mem.eql(u8, command, "azure-gallery-verify")) {
        var options = try parse(allocator, argv, &.{
            "--request",
            "--response",
            "--image-version-id",
        });
        defer options.deinit();
        return galleryVerify(
            allocator,
            io,
            out,
            try options.require("--request"),
            try options.require("--response"),
            try options.require("--image-version-id"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "azure-vm-security")) {
        var options = try parse(allocator, argv, &.{ "--vm", "--instance" });
        defer options.deinit();
        for ([_][]const u8{
            try options.require("--vm"),
            try options.require("--instance"),
        }) |path| {
            var document = try support.readObject(allocator, io, path, diagnostic);
            defer document.deinit();
            const profile = document.object();
            if (!support.stringIs(profile.get("securityType"), "TrustedLaunch")) {
                return fail(diagnostic, "{s}: VM is not Trusted Launch", .{path});
            }
            const settings = support.objectOf(profile.get("uefiSettings"));
            const secure_boot = if (settings) |object|
                object.get("secureBootEnabled")
            else
                null;
            if (!support.isTrue(secure_boot)) return fail(
                diagnostic,
                "{s}: Secure Boot is not enabled",
                .{path},
            );
            const vtpm = if (settings) |object| object.get("vTpmEnabled") else null;
            if (!support.isTrue(vtpm)) return fail(
                diagnostic,
                "{s}: vTPM is not enabled",
                .{path},
            );
        }
        return;
    }
    if (std.mem.eql(u8, command, "azure-uefi-db")) {
        var options = try parse(allocator, argv, &.{
            "--report",
            "--certificate-sha256",
        });
        defer options.deinit();
        return uefiDb(
            allocator,
            io,
            try options.require("--report"),
            try options.require("--certificate-sha256"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "cloud-init-status")) {
        var options = try parse(allocator, argv, &.{});
        defer options.deinit();
        return statusFromStdin(allocator, io, out, diagnostic);
    }
    if (std.mem.eql(u8, command, "publish-expected")) {
        var options = try parse(allocator, argv, &.{
            "--manifest",
            "--assets-dir",
            "--release-tag",
            "--source-commit",
        });
        defer options.deinit();
        return publishExpected(
            allocator,
            io,
            out,
            try options.require("--manifest"),
            try options.require("--assets-dir"),
            try options.require("--release-tag"),
            try options.require("--source-commit"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "github-tag-object")) {
        var options = try parse(allocator, argv, &.{ "--refs", "--tag" });
        defer options.deinit();
        var parsed = try readValue(
            allocator,
            io,
            try options.require("--refs"),
            diagnostic,
        );
        defer parsed.deinit();
        const items = support.arrayOf(parsed.value) orelse return fail(
            diagnostic,
            "tag ref listing is not a JSON array",
            .{},
        );
        const tag = try options.require("--tag");
        var expected_buffer: [256]u8 = undefined;
        const expected = std.fmt.bufPrint(
            &expected_buffer,
            "refs/tags/{s}",
            .{tag},
        ) catch return fail(diagnostic, "release tag is too long", .{});
        var match: ?std.json.ObjectMap = null;
        var matches: usize = 0;
        for (items) |item| {
            const entry = support.objectOf(item) orelse continue;
            if (!support.stringIs(entry.get("ref"), expected)) continue;
            matches += 1;
            match = entry;
        }
        if (matches > 1) return fail(diagnostic, "duplicate exact tag refs", .{});
        if (match) |entry| {
            const object = support.objectOf(entry.get("object")) orelse return fail(
                diagnostic,
                "tag ref object identity is absent",
                .{},
            );
            const kind = support.stringOf(object.get("type")) orelse return fail(
                diagnostic,
                "tag ref object identity is absent",
                .{},
            );
            const sha = support.stringOf(object.get("sha")) orelse return fail(
                diagnostic,
                "tag ref object identity is absent",
                .{},
            );
            try out.print("{s}\n{s}\n", .{ kind, sha });
        }
        return;
    }
    if (std.mem.eql(u8, command, "github-tag-target")) {
        var options = try parse(allocator, argv, &.{"--object"});
        defer options.deinit();
        var document = try support.readObject(
            allocator,
            io,
            try options.require("--object"),
            diagnostic,
        );
        defer document.deinit();
        const object = support.objectOf(document.get("object")) orelse return fail(
            diagnostic,
            "tag object identity is absent",
            .{},
        );
        const kind = support.stringOf(object.get("type")) orelse return fail(
            diagnostic,
            "tag object identity is absent",
            .{},
        );
        const sha = support.stringOf(object.get("sha")) orelse return fail(
            diagnostic,
            "tag object identity is absent",
            .{},
        );
        try out.print("{s}\n{s}\n", .{ kind, sha });
        return;
    }
    if (std.mem.eql(u8, command, "github-stale-assets")) {
        var options = try parse(allocator, argv, &.{ "--release", "--expected" });
        defer options.deinit();
        var expected = try readExpected(
            allocator,
            io,
            try options.require("--expected"),
            diagnostic,
        );
        defer expected.deinit(allocator);
        var document = try support.readObject(
            allocator,
            io,
            try options.require("--release"),
            diagnostic,
        );
        defer document.deinit();
        const assets = support.arrayOf(document.get("assets")) orelse return fail(
            diagnostic,
            "release asset listing is absent",
            .{},
        );
        for (assets) |asset| {
            const entry = support.objectOf(asset) orelse return fail(
                diagnostic,
                "release asset listing is absent",
                .{},
            );
            const name = support.stringOf(entry.get("name")) orelse return fail(
                diagnostic,
                "release asset listing is absent",
                .{},
            );
            if (expected.find(name) != null) continue;
            const id = support.integerOf(entry.get("id")) orelse return fail(
                diagnostic,
                "release asset listing is absent",
                .{},
            );
            try out.print("{d}\n", .{id});
        }
        return;
    }
    if (std.mem.eql(u8, command, "github-release-assets")) {
        var options = try parse(allocator, argv, &.{
            "--release",
            "--expected",
            "--stage",
        });
        defer options.deinit();
        return releaseAssets(
            allocator,
            io,
            try options.require("--release"),
            try options.require("--expected"),
            try options.require("--stage"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, command, "github-release-downloaded")) {
        var options = try parse(allocator, argv, &.{ "--dir", "--expected" });
        defer options.deinit();
        return releaseDownloaded(
            allocator,
            io,
            try options.require("--dir"),
            try options.require("--expected"),
            diagnostic,
        );
    }
    return error.Usage;
}

fn requestUefiSettings(
    request: *const std.json.ObjectMap,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    return documents.galleryUefiSettings(request) orelse fail(
        diagnostic,
        "Azure gallery request omitted custom UEFI settings",
        .{},
    );
}

/// The inline QCOW2 check both build jobs and the local end-to-end driver run
/// against `miz info --output=json`.
pub fn verifyImageInfo(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    virtual_size: i64,
    virtual_size_label: ?[]const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var document = try support.readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const info = document.object();
    if (!support.stringIs(info.get("format"), "qcow2")) return fail(
        diagnostic,
        "candidate is not QCOW2",
        .{},
    );
    if (support.integerOf(info.get("virtual-size")) != virtual_size) {
        if (virtual_size_label) |label| return fail(
            diagnostic,
            "candidate virtual size is not exactly {s}",
            .{label},
        );
        return fail(
            diagnostic,
            "candidate virtual size is not exactly {d} bytes",
            .{virtual_size},
        );
    }
    if (isTruthy(info.get("backing-filename")) or
        isTruthy(info.get("full-backing-filename")))
    {
        return fail(diagnostic, "candidate has a backing file", .{});
    }
    const data = nestedObject(
        .{ .object = info.* },
        &.{ "format-specific", "data" },
    );
    const compression = if (data) |object|
        object.get("compression-type")
    else
        null;
    if (!support.stringIs(compression, "zstd")) return fail(
        diagnostic,
        "candidate does not use zstd cluster compression",
        .{},
    );
}

/// Translates a size-inventory rejection into this module's failure shape.
/// The measurement module already produced the operator-facing sentence.
fn inventoryFailure(err: size_inventory.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Failed => error.Failed,
    };
}

/// Parses a comma-separated `--require-phase` list.
fn requiredPhases(
    allocator: Allocator,
    text: ?[]const u8,
    diagnostic: *Diagnostic,
) Error![]size_inventory.Phase {
    const list = text orelse return allocator.dupe(
        size_inventory.Phase,
        &.{.root_build},
    );
    var phases: std.ArrayList(size_inventory.Phase) = .empty;
    errdefer phases.deinit(allocator);
    var names = std.mem.splitScalar(u8, list, ',');
    while (names.next()) |name| {
        const trimmed = std.mem.trim(u8, name, " ");
        if (trimmed.len == 0) continue;
        const phase = size_inventory.Phase.parse(trimmed) orelse return fail(
            diagnostic,
            "unknown size inventory phase {s}",
            .{trimmed},
        );
        try phases.append(allocator, phase);
    }
    if (phases.items.len == 0) return fail(
        diagnostic,
        "--require-phase named no phases",
        .{},
    );
    return phases.toOwnedSlice(allocator);
}

/// `size-inventory-verify`: re-checks a size-inventory document and prints the
/// totals a reviewer needs before a closure change is proposed.
///
/// `--max-unexpected-unowned` turns the reported remainder into a gate. Issue
/// #677 step 3 requires the fresh roots to carry no unowned payload outside the
/// explicit injected-file allowlist, so their workflows pass `0`; a document
/// without the bound is verified but not gated, which is what the `full` flavor
/// and the pre-change benchmark comparisons need.
pub fn sizeInventoryVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    report_path: []const u8,
    architecture: ?[]const u8,
    flavor: ?[]const u8,
    require_phase: ?[]const u8,
    max_unexpected_unowned: ?[]const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    const unexpected_bound: ?u64 = if (max_unexpected_unowned) |text|
        std.fmt.parseInt(u64, text, 10) catch return fail(
            diagnostic,
            "--max-unexpected-unowned must be a non-negative integer, not {s}",
            .{text},
        )
    else
        null;
    const phases = try requiredPhases(allocator, require_phase, diagnostic);
    defer allocator.free(phases);
    var parsed = size_inventory.readValidated(allocator, io, report_path, .{
        .architecture = architecture,
        .flavor = flavor,
        .required_phases = phases,
    }, diagnostic) catch |err| return inventoryFailure(err);
    defer parsed.deinit();
    const summary = size_inventory.validateDocument(
        allocator,
        parsed.value,
        .{ .architecture = architecture, .flavor = flavor, .required_phases = phases },
        diagnostic,
    ) catch |err| return inventoryFailure(err);
    if (unexpected_bound) |bound| {
        if (summary.unexpected_unowned_count > bound) return fail(
            diagnostic,
            "size inventory carries {d} unowned path(s) outside the explicit " ++
                "allowlist, which is more than the {d} allowed",
            .{ summary.unexpected_unowned_count, bound },
        );
    }
    try out.print(
        "{s} {s} packages={d} installed_bytes={d} allocated_bytes={d} " ++
            "unexpected_unowned={d} unowned_policy={s} closure={s}\n",
        .{
            summary.architecture,
            summary.flavor,
            summary.package_count,
            summary.installed_bytes,
            summary.allocated_bytes,
            summary.unexpected_unowned_count,
            summary.unowned_policy_sha256,
            summary.closure_sha256,
        },
    );
}

/// Translates a disk-geometry rejection into this module's failure shape. The
/// geometry module already produced the operator-facing sentence.
fn geometryFailure(err: disk_geometry.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Failed => error.Failed,
    };
}

/// `disk-geometry-verify`: re-checks a published core disk-geometry report
/// (issue #677 step 5).
///
/// The check is not "does the file parse". The validator recomputes the whole
/// plan from the document's own measurements and policy and requires the
/// published offsets, lengths, and virtual size to be exactly what those
/// inputs produce -- and refuses a plan that lands back on the retired
/// inherited 3584 MiB geometry. `--virtual-size` binds the report to the
/// artifact the same run measured, so a geometry document for some other
/// build cannot be presented alongside this one.
pub fn diskGeometryVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    geometry_path: []const u8,
    architecture: ?[]const u8,
    flavor: ?[]const u8,
    virtual_size: ?[]const u8,
    github_env: ?[]const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    const expected_size: ?u64 = if (virtual_size) |text|
        std.fmt.parseInt(u64, text, 10) catch return fail(
            diagnostic,
            "--virtual-size must be a non-negative integer, not {s}",
            .{text},
        )
    else
        null;
    var parsed = disk_geometry.readValidated(allocator, io, geometry_path, .{
        .architecture = architecture,
        .flavor = flavor,
        .virtual_size = expected_size,
    }, diagnostic) catch |err| return geometryFailure(err);
    defer parsed.deinit();
    const summary = disk_geometry.validateDocument(
        parsed.value(),
        .{
            .architecture = architecture,
            .flavor = flavor,
            .virtual_size = expected_size,
        },
        diagnostic,
    ) catch |err| return geometryFailure(err);
    // The calculated size is the workflow's only source for the artifact size
    // it then checks the image against: nothing in the workflow may name a
    // size of its own, or the plan would stop being what the image is.
    if (github_env) |path| {
        const label = support.contract.formatMib(summary.virtual_size);
        var lines: std.ArrayList(u8) = .empty;
        defer lines.deinit(allocator);
        try lines.print(
            allocator,
            "VIRTUAL_SIZE={d}\nVIRTUAL_SIZE_LABEL={s}\n",
            .{ summary.virtual_size, label.slice() },
        );
        appendFile(io, path, lines.items) catch |err| return fail(
            diagnostic,
            "cannot write {s}: {s}",
            .{ path, @errorName(err) },
        );
    }
    try out.print(
        "{s} {s} virtual_size={d} esp_bytes={d} root_bytes={d} " ++
            "root_free_bytes={d} uki_bytes={d}\n",
        .{
            summary.architecture,
            summary.flavor,
            summary.virtual_size,
            summary.esp_length_bytes,
            summary.root_length_bytes,
            summary.root_free_bytes,
            summary.signed_uki_bytes,
        },
    );
}

/// Translates a runtime-contract rejection into this module's failure shape.
/// The contract module already produced the operator-facing sentence.
fn contractFailure(err: runtime_contract_document.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Failed => error.Failed,
    };
}

/// `runtime-contract-verify`: re-checks a published runtime-contract document
/// against the contract this tool was compiled with (issue #677 step 2).
///
/// The check is deliberately not "does the file parse". A candidate carries
/// this document so a reviewer can see what it promised; a document that no
/// longer matches the compiled contract means the promise and the enforcement
/// have separated, which is the one failure a size-minimization program cannot
/// afford to discover late.
pub fn runtimeContractVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    contract_path: []const u8,
    architecture: ?[]const u8,
    flavor: ?[]const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var parsed = runtime_contract_document.readValidated(allocator, io, contract_path, .{
        .architecture = architecture,
        .flavor = flavor,
    }, diagnostic) catch |err| return contractFailure(err);
    defer parsed.deinit();
    const summary = runtime_contract_document.validateDocument(
        parsed.value,
        .{ .architecture = architecture, .flavor = flavor },
        diagnostic,
    ) catch |err| return contractFailure(err);
    try out.print(
        "{s} {s} requirements={d} guest_runtime={d} build_tooling={d} " ++
            "acceptance_only={d} contract={s}\n",
        .{
            summary.architecture,
            summary.flavor,
            summary.total,
            summary.guest_runtime,
            summary.build_tooling,
            summary.acceptance_only,
            summary.contract_sha256,
        },
    );
}

/// `build-runtime-split-verify`: re-checks that a published core build kept its
/// build-time dependencies out of the final guest (issue #677 step 4).
///
/// The builder already refuses to publish an image that failed the split, and
/// candidate verification already validates the whole `debz` binding. This gate
/// exists so the separation fails in CI under its own name, with the packages
/// that crossed the line in the message, instead of inside a generic provenance
/// rejection that a reader has to decode.
pub fn buildRuntimeSplitVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    provenance_path: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var document = try support.readObject(allocator, io, provenance_path, diagnostic);
    defer document.deinit();
    const debz = support.objectOf(document.object().get("debz")) orelse return fail(
        diagnostic,
        "build provenance has no debz binding",
        .{},
    );
    const roots = support.arrayOf(debz.get("package_roots")) orelse return fail(
        diagnostic,
        "build provenance has no package roots",
        .{},
    );
    const selection = contracts.validateCorePackageRoots(roots) catch return fail(
        diagnostic,
        "build provenance package roots are not a kernel selection followed by " ++
            "the contract's literal guest roots",
        .{},
    );

    const selector = runtime_contract.kernel_templates.selector;
    for (roots) |entry| {
        const name = support.stringOf(entry) orelse "";
        if (std.mem.eql(u8, name, selector)) return fail(
            diagnostic,
            "kernel metapackage {s} is a guest package root; it is resolved to " ++
                "select {s} and must not be installed",
            .{ selector, selection.image_package },
        );
    }

    const stage = support.objectOf(debz.get("build_stage")) orelse return fail(
        diagnostic,
        "build provenance records no initramfs build stage, so the guest " ++
            "generated its own initramfs",
        .{},
    );
    const stage_roots = support.arrayOf(stage.get("package_roots")) orelse return fail(
        diagnostic,
        "the initramfs build stage records no package roots",
        .{},
    );
    if (stage_roots.len == 0) return fail(
        diagnostic,
        "the initramfs build stage records no package roots",
        .{},
    );
    for (stage_roots) |stage_entry| {
        const build_root = support.stringOf(stage_entry) orelse return fail(
            diagnostic,
            "the initramfs build stage roots are invalid",
            .{},
        );
        if (!runtime_contract.isBuildPackageRoot(build_root)) return fail(
            diagnostic,
            "{s} is a build-stage root the runtime contract does not classify " ++
                "as build tooling",
            .{build_root},
        );
        for (roots) |entry| {
            const name = support.stringOf(entry) orelse "";
            if (std.mem.eql(u8, name, build_root)) return fail(
                diagnostic,
                "build-only package {s} is also a guest package root",
                .{build_root},
            );
        }
    }

    const initramfs = support.objectOf(stage.get("initramfs")) orelse return fail(
        diagnostic,
        "the initramfs build stage records no output",
        .{},
    );
    if (!support.stringIs(initramfs.get("kernel_release"), selection.release)) return fail(
        diagnostic,
        "the staged initramfs was not built for the selected kernel {s}",
        .{selection.release},
    );

    try out.print(
        "kernel={s} image={s} modules={s} guest_roots={d} build_roots={d}\n",
        .{
            selection.release,
            selection.image_package,
            selection.modules_package,
            roots.len,
            stage_roots.len,
        },
    );
}

/// `runtime-contract-probe-verify`: judges a guest probe report.
///
/// The report is produced inside the guest by the static probe acceptance
/// uploads, so the shell harness never has to know the contract; it only has
/// to hand the captured output here. A guest requirement that is not `ok`, a
/// requirement the probe failed to report at all, and an unparseable line are
/// all refusals -- a partial report must never read as a pass.
pub fn runtimeContractProbeVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    report_path: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    const text = support.file_support.readBounded(
        allocator,
        io,
        report_path,
        runtime_contract_document.document_max_bytes,
    ) catch |err| return fail(
        diagnostic,
        "cannot read runtime contract probe report {s}: {s}",
        .{ report_path, @errorName(err) },
    );
    defer allocator.free(text);
    runtime_contract_document.verifyProbeReport(text, diagnostic) catch |err|
        return contractFailure(err);
    try out.print("runtime-contract satisfied\n", .{});
}

/// `runtime-contract-requirement`: judges one named requirement out of a
/// partial probe report.
///
/// The full report is the core appliance's whole contract. Secure Boot and
/// kernel lockdown are platform facts every flavor is held to, and acceptance
/// asks the probe for those by name rather than mounting securityfs with a
/// `mount(8)` the image would then have to keep. `--id` takes a
/// comma-separated list, and every one of them must be present and `ok`: a
/// requirement the report never mentioned is a refusal, not a pass.
pub fn runtimeContractRequirement(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    report_path: []const u8,
    ids: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    const text = support.file_support.readBounded(
        allocator,
        io,
        report_path,
        runtime_contract_document.document_max_bytes,
    ) catch |err| return fail(
        diagnostic,
        "cannot read runtime contract probe report {s}: {s}",
        .{ report_path, @errorName(err) },
    );
    defer allocator.free(text);

    var names = std.mem.splitScalar(u8, ids, ',');
    var checked: usize = 0;
    while (names.next()) |raw| {
        const id = std.mem.trim(u8, raw, " \t");
        if (id.len == 0) continue;
        if (runtime_contract.lookup(id) == null) return fail(
            diagnostic,
            "{s} is not a runtime contract requirement",
            .{id},
        );
        const status = runtime_contract.statusOf(text, id) orelse return fail(
            diagnostic,
            "the probe report never mentions {s}",
            .{id},
        );
        if (status != .ok) return fail(
            diagnostic,
            "runtime contract requirement {s} is {s}",
            .{ id, status.key() },
        );
        checked += 1;
    }
    if (checked == 0) return fail(diagnostic, "no requirement was named", .{});
    try out.print("runtime-contract requirements satisfied\n", .{});
}

/// `size-inventory-compare`: the benchmark comparison #677 asks for before the
/// closure is changed. It reports what moved between two measured images and
/// refuses to compare documents that do not describe the same image.
pub fn sizeInventoryCompare(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    baseline_path: []const u8,
    candidate_path: []const u8,
    output_path: ?[]const u8,
    step_summary: ?[]const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var baseline = size_inventory.readValidated(
        allocator,
        io,
        baseline_path,
        .{},
        diagnostic,
    ) catch |err| return inventoryFailure(err);
    defer baseline.deinit();
    var candidate = size_inventory.readValidated(
        allocator,
        io,
        candidate_path,
        .{},
        diagnostic,
    ) catch |err| return inventoryFailure(err);
    defer candidate.deinit();

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    var scratch: std.heap.ArenaAllocator = .init(allocator);
    defer scratch.deinit();
    const comparison = size_inventory.compareAlloc(
        arena.allocator(),
        scratch.allocator(),
        baseline.value,
        candidate.value,
        diagnostic,
    ) catch |err| return inventoryFailure(err);

    if (output_path) |path| {
        try support.writeDocument(allocator, io, path, comparison, diagnostic);
    }
    const root = support.objectOf(comparison.object.get("root_build")).?;
    const packages = support.integerOf(root.get("package_count_delta")).?;
    const installed = support.integerOf(root.get("installed_bytes_delta")).?;
    const allocated = support.integerOf(root.get("allocated_bytes_delta")).?;
    const closure_changed = support.isTrue(root.get("closure_changed"));
    try out.print(
        "packages={d} installed_bytes={d} allocated_bytes={d} closure_changed={}\n",
        .{ packages, installed, allocated, closure_changed },
    );
    if (step_summary) |path| {
        var lines: std.ArrayList(u8) = .empty;
        defer lines.deinit(allocator);
        try lines.print(
            allocator,
            "### Ubuntu 26.04 size inventory\n\n" ++
                "| measure | delta |\n| --- | --- |\n" ++
                "| packages | {d} |\n" ++
                "| installed bytes | {d} |\n" ++
                "| allocated bytes | {d} |\n" ++
                "| closure changed | {} |\n",
            .{ packages, installed, allocated, closure_changed },
        );
        appendFile(io, path, lines.items) catch |err| return fail(
            diagnostic,
            "cannot write {s}: {s}",
            .{ path, @errorName(err) },
        );
    }
}

/// Exports the candidate's signing bindings: writes the canonical DER
/// certificate, prints the three digests, and optionally appends the workflow
/// environment values the acceptance harness reads.
pub fn candidateSigningEnv(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    manifest_path: []const u8,
    certificate_path: []const u8,
    github_env: ?[]const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var document = try support.readObject(allocator, io, manifest_path, diagnostic);
    defer document.deinit();
    const signing = support.objectOf(document.get("uki_signing")) orelse return fail(
        diagnostic,
        "candidate signing bindings are malformed",
        .{},
    );
    const image_sha256 = support.stringOf(document.get("sha256")) orelse "";
    const certificate_sha256 = support.stringOf(
        signing.get("certificate_sha256"),
    ) orelse "";
    const uki_sha256 = support.stringOf(signing.get("fallback_uki_sha256")) orelse "";
    for ([_][]const u8{ image_sha256, certificate_sha256, uki_sha256 }) |value| {
        if (!support.isSha256(value)) return fail(
            diagnostic,
            "candidate signing bindings are malformed",
            .{},
        );
    }
    const encoded = support.stringOf(
        signing.get("certificate_der_base64"),
    ) orelse return fail(
        diagnostic,
        "candidate signing certificate binding is invalid",
        .{},
    );
    const certificate = provenance.decodeBase64(allocator, encoded) catch
        return fail(
            diagnostic,
            "candidate signing certificate binding is invalid",
            .{},
        );
    defer allocator.free(certificate);
    if (certificate.len == 0 or !std.mem.eql(
        u8,
        &support.digest.hexBytes(certificate),
        certificate_sha256,
    )) {
        return fail(
            diagnostic,
            "candidate signing certificate binding is invalid",
            .{},
        );
    }
    Dir.cwd().writeFile(io, .{
        .sub_path = certificate_path,
        .data = certificate,
    }) catch |err| return fail(
        diagnostic,
        "cannot write {s}: {s}",
        .{ certificate_path, @errorName(err) },
    );

    if (github_env) |path| {
        var lines: std.ArrayList(u8) = .empty;
        defer lines.deinit(allocator);
        try lines.print(
            allocator,
            "MIZ_UBUNTU2604_IMAGE_SHA256={s}\n" ++
                "MIZ_UBUNTU2604_SIGNING_CERTIFICATE_SHA256={s}\n" ++
                "MIZ_UBUNTU2604_UKI_SHA256={s}\n",
            .{ image_sha256, certificate_sha256, uki_sha256 },
        );
        appendFile(io, path, lines.items) catch |err| return fail(
            diagnostic,
            "cannot write {s}: {s}",
            .{ path, @errorName(err) },
        );
    }
    try out.print("{s}\n{s}\n{s}\n", .{
        image_sha256,
        certificate_sha256,
        uki_sha256,
    });
}

fn appendFile(io: Io, path: []const u8, data: []const u8) !void {
    const file = try Dir.cwd().createFile(io, path, .{
        .truncate = false,
        .read = false,
    });
    defer file.close(io);
    const end = (try file.stat(io)).size;
    try file.writePositionalAll(io, data, end);
}

pub const ArtifactKind = enum {
    candidate,
    native,
    azure,

    pub fn parse(text: []const u8) ?ArtifactKind {
        inline for (std.meta.tags(ArtifactKind)) |kind| {
            if (std.mem.eql(u8, text, @tagName(kind))) return kind;
        }
        return null;
    }

    fn artifactPrefix(self: ArtifactKind) []const u8 {
        return switch (self) {
            .candidate => "ubuntu2604-candidate",
            .native => "ubuntu2604-native",
            .azure => "ubuntu2604-azure",
        };
    }
};

pub const ResolveArtifactsOptions = struct {
    jobs: []const u8,
    artifacts: []const u8,
    kind: ArtifactKind,
    run_id: []const u8,
    source_commit: []const u8,
    max_attempt: i64,
    output: []const u8,
};

fn isDiagnosticArtifact(kind: ArtifactKind, name: []const u8) bool {
    return switch (kind) {
        .candidate => false,
        .native => std.mem.startsWith(u8, name, "ubuntu2604-native-failure-"),
        .azure => std.mem.startsWith(u8, name, "ubuntu2604-azure-failure-"),
    };
}

fn validateArtifactInventory(
    kind: ArtifactKind,
    artifacts: []const std.json.Value,
    source_commit: []const u8,
    max_attempt: i64,
    diagnostic: *Diagnostic,
) Error!void {
    var prefix_buffer: [96]u8 = undefined;
    const kind_prefix = std.fmt.bufPrint(
        &prefix_buffer,
        "{s}-",
        .{kind.artifactPrefix()},
    ) catch unreachable;

    for (artifacts, 0..) |value, index| {
        const artifact = support.objectOf(value) orelse return fail(
            diagnostic,
            "artifact selection contains a malformed artifact",
            .{},
        );
        const name = support.stringOf(artifact.get("name")) orelse return fail(
            diagnostic,
            "artifact selection contains a malformed artifact",
            .{},
        );
        if (!std.mem.startsWith(u8, name, kind_prefix) or
            isDiagnosticArtifact(kind, name))
        {
            continue;
        }
        for (artifacts[0..index]) |earlier_value| {
            const earlier = support.objectOf(earlier_value) orelse return fail(
                diagnostic,
                "artifact selection contains a malformed artifact",
                .{},
            );
            if (support.stringIs(earlier.get("name"), name)) return fail(
                diagnostic,
                "duplicate {s} artifact: {s}",
                .{ @tagName(kind), name },
            );
        }

        var matched_key = false;
        for (contracts.release_order) |key| {
            var key_prefix_buffer: [128]u8 = undefined;
            const key_prefix = std.fmt.bufPrint(
                &key_prefix_buffer,
                "{s}-{s}-",
                .{ kind.artifactPrefix(), key },
            ) catch unreachable;
            if (!std.mem.startsWith(u8, name, key_prefix)) continue;
            matched_key = true;

            const suffix = name[key_prefix.len..];
            if (suffix.len <= source_commit.len or
                !std.mem.eql(u8, suffix[0..source_commit.len], source_commit) or
                suffix[source_commit.len] != '-')
            {
                return fail(
                    diagnostic,
                    "{s}: {s} artifact source is not exact",
                    .{ key, @tagName(kind) },
                );
            }
            const attempt = positiveDecimal(suffix[source_commit.len + 1 ..]) orelse
                return fail(
                    diagnostic,
                    "{s}: {s} artifact attempt is invalid",
                    .{ key, @tagName(kind) },
                );
            if (attempt > max_attempt) return fail(
                diagnostic,
                "{s}: {s} artifact attempt exceeds the run",
                .{ key, @tagName(kind) },
            );
            break;
        }
        if (!matched_key) return fail(
            diagnostic,
            "{s} artifact key is not recognized: {s}",
            .{ @tagName(kind), name },
        );
    }
}

/// Selects the newest artifact for each release key only when the artifact and
/// its corresponding job agree on run, attempt, source, and successful status.
pub fn resolveArtifacts(
    allocator: Allocator,
    io: Io,
    options: ResolveArtifactsOptions,
    diagnostic: *Diagnostic,
) Error!void {
    const run_id = positiveDecimal(options.run_id) orelse return fail(
        diagnostic,
        "artifact selection run id is invalid",
        .{},
    );
    if (!support.isCommit(options.source_commit)) return fail(
        diagnostic,
        "artifact selection source commit is invalid",
        .{},
    );
    if (options.max_attempt <= 0 or options.max_attempt > 1000) return fail(
        diagnostic,
        "artifact selection maximum attempt is invalid",
        .{},
    );

    var jobs_document = try readValue(allocator, io, options.jobs, diagnostic);
    defer jobs_document.deinit();
    const jobs = support.arrayOf(jobs_document.value) orelse return fail(
        diagnostic,
        "artifact selection jobs document is not an array",
        .{},
    );
    var artifacts_document = try readValue(
        allocator,
        io,
        options.artifacts,
        diagnostic,
    );
    defer artifacts_document.deinit();
    const artifacts = support.arrayOf(artifacts_document.value) orelse return fail(
        diagnostic,
        "artifact selection artifacts document is not an array",
        .{},
    );
    try validateArtifactInventory(
        options.kind,
        artifacts,
        options.source_commit,
        options.max_attempt,
        diagnostic,
    );

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());
    var selected = builder.object();

    for (contracts.release_order) |key| {
        var selected_entry: ?std.json.Value = null;
        var attempt = options.max_attempt;
        while (attempt > 0) : (attempt -= 1) {
            const artifact_name = try std.fmt.allocPrint(
                allocator,
                "{s}-{s}-{s}-{d}",
                .{
                    options.kind.artifactPrefix(),
                    key,
                    options.source_commit,
                    attempt,
                },
            );
            defer allocator.free(artifact_name);

            var artifact_match: ?std.json.ObjectMap = null;
            var artifact_count: usize = 0;
            for (artifacts) |value| {
                const artifact = support.objectOf(value) orelse continue;
                if (support.stringIs(artifact.get("name"), artifact_name)) {
                    artifact_count += 1;
                    artifact_match = artifact;
                }
            }
            if (artifact_count > 1) return fail(
                diagnostic,
                "{s}: duplicate {s} artifact for attempt {d}",
                .{ key, @tagName(options.kind), attempt },
            );
            if (artifact_count == 0) continue;

            const artifact = artifact_match.?;
            const artifact_id = positiveInteger(artifact.get("id")) orelse
                return fail(
                    diagnostic,
                    "{s}: selected {s} artifact id is invalid",
                    .{ key, @tagName(options.kind) },
                );
            const size = positiveInteger(artifact.get("size_in_bytes")) orelse
                return fail(
                    diagnostic,
                    "{s}: selected {s} artifact is empty",
                    .{ key, @tagName(options.kind) },
                );
            _ = size;
            const expired = artifact.get("expired") orelse return fail(
                diagnostic,
                "{s}: selected {s} artifact expiry is invalid",
                .{ key, @tagName(options.kind) },
            );
            if (expired != .bool or expired.bool) return fail(
                diagnostic,
                "{s}: selected {s} artifact is expired",
                .{ key, @tagName(options.kind) },
            );
            const digest = support.stringOf(artifact.get("digest")) orelse
                return fail(
                    diagnostic,
                    "{s}: selected {s} artifact digest is invalid",
                    .{ key, @tagName(options.kind) },
                );
            if (!validArtifactDigest(digest)) return fail(
                diagnostic,
                "{s}: selected {s} artifact digest is invalid",
                .{ key, @tagName(options.kind) },
            );
            const artifact_workflow = support.objectOf(
                artifact.get("workflow_run"),
            ) orelse return fail(
                diagnostic,
                "{s}: selected {s} artifact workflow is invalid",
                .{ key, @tagName(options.kind) },
            );
            if (support.integerOf(artifact_workflow.get("id")) != run_id or
                !support.stringIs(
                    artifact_workflow.get("head_sha"),
                    options.source_commit,
                ))
            {
                return fail(
                    diagnostic,
                    "{s}: selected {s} artifact workflow is not exact",
                    .{ key, @tagName(options.kind) },
                );
            }

            const job_name = try expectedJobName(allocator, options.kind, key);
            defer allocator.free(job_name);
            var job_match: ?std.json.ObjectMap = null;
            var job_count: usize = 0;
            for (jobs) |value| {
                const job = support.objectOf(value) orelse continue;
                if (support.stringIs(job.get("name"), job_name) and
                    support.integerOf(job.get("run_attempt")) == attempt)
                {
                    job_count += 1;
                    job_match = job;
                }
            }
            if (job_count != 1) return fail(
                diagnostic,
                "{s}: selected {s} artifact does not have one exact job",
                .{ key, @tagName(options.kind) },
            );
            const job = job_match.?;
            const job_id = positiveInteger(job.get("id")) orelse return fail(
                diagnostic,
                "{s}: selected {s} job id is invalid",
                .{ key, @tagName(options.kind) },
            );
            if (!support.stringIs(job.get("status"), "completed") or
                !support.stringIs(job.get("conclusion"), "success") or
                support.integerOf(job.get("run_id")) != run_id or
                !support.stringIs(job.get("head_sha"), options.source_commit))
            {
                return fail(
                    diagnostic,
                    "{s}: selected {s} job was not successful and exact",
                    .{ key, @tagName(options.kind) },
                );
            }

            var entry = builder.object();
            try builder.putInteger(&entry, "artifact_id", artifact_id);
            try builder.putString(&entry, "artifact_name", artifact_name);
            try builder.putString(&entry, "artifact_digest", digest);
            try builder.putInteger(&entry, "job_id", job_id);
            try builder.putString(&entry, "job_name", job_name);
            try builder.put(
                &entry,
                "run_attempt",
                try builder.print("{d}", .{attempt}),
            );
            selected_entry = .{ .object = entry };
            break;
        }
        const entry = selected_entry orelse return fail(
            diagnostic,
            "{s}: no valid {s} artifact was found",
            .{ key, @tagName(options.kind) },
        );
        try builder.put(&selected, key, entry);
    }

    var document = builder.object();
    try builder.putInteger(&document, "schema", 1);
    try builder.putString(
        &document,
        "type",
        "miz-ubuntu2604-artifact-selection",
    );
    try builder.putString(&document, "kind", @tagName(options.kind));
    try builder.putString(&document, "run_id", options.run_id);
    try builder.putString(&document, "source_commit", options.source_commit);
    try builder.put(&document, "artifacts", .{ .object = selected });
    try support.writeDocument(
        allocator,
        io,
        options.output,
        .{ .object = document },
        diagnostic,
    );
}

fn positiveDecimal(text: []const u8) ?i64 {
    if (text.len == 0 or text[0] == '0') return null;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    const value = std.fmt.parseInt(i64, text, 10) catch return null;
    return if (value > 0) value else null;
}

fn positiveInteger(value: ?std.json.Value) ?i64 {
    const number = support.integerOf(value) orelse return null;
    return if (number > 0) number else null;
}

fn validArtifactDigest(text: []const u8) bool {
    return std.mem.startsWith(u8, text, "sha256:") and
        support.isSha256(text["sha256:".len..]);
}

fn expectedJobName(
    allocator: Allocator,
    kind: ArtifactKind,
    key: []const u8,
) Error![]u8 {
    return switch (kind) {
        .candidate => std.fmt.allocPrint(allocator, "build/native {s}", .{key}),
        .native => std.fmt.allocPrint(
            allocator,
            "same-architecture QEMU ({s}) {s}",
            .{
                if (std.mem.startsWith(u8, key, "x86_64")) "kvm" else "tcg",
                key,
            },
        ),
        .azure => std.fmt.allocPrint(allocator, "Azure {s}", .{key}),
    };
}

pub const ReleaseGateOptions = struct {
    candidates: []const u8,
    native_results: []const u8,
    azure_results: []const u8,
    candidate_selection: []const u8,
    native_selection: []const u8,
    azure_selection: []const u8,
    source_commit: []const u8,
    candidate_run_id: []const u8,
    run_id: []const u8,
};

fn loadArtifactSelection(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    kind: ArtifactKind,
    run_id: []const u8,
    source_commit: []const u8,
    diagnostic: *Diagnostic,
) Error!std.json.Parsed(std.json.Value) {
    var parsed = try readValue(allocator, io, path, diagnostic);
    errdefer parsed.deinit();
    const document = support.objectOf(parsed.value) orelse return fail(
        diagnostic,
        "{s} artifact selection is malformed",
        .{@tagName(kind)},
    );
    if (!support.hasExactFields(document, &.{
        "schema",
        "type",
        "kind",
        "run_id",
        "source_commit",
        "artifacts",
    }) or
        support.integerOf(document.get("schema")) != 1 or
        !support.stringIs(
            document.get("type"),
            "miz-ubuntu2604-artifact-selection",
        ) or
        !support.stringIs(document.get("kind"), @tagName(kind)) or
        !support.stringIs(document.get("run_id"), run_id) or
        !support.stringIs(document.get("source_commit"), source_commit))
    {
        return fail(
            diagnostic,
            "{s} artifact selection identity is not exact",
            .{@tagName(kind)},
        );
    }
    const artifacts = support.objectOf(document.get("artifacts")) orelse
        return fail(
            diagnostic,
            "{s} artifact selection matrix is malformed",
            .{@tagName(kind)},
        );
    if (artifacts.count() != contracts.release_order.len) return fail(
        diagnostic,
        "{s} artifact selection matrix is not exact",
        .{@tagName(kind)},
    );

    var artifact_ids: [contracts.release_order.len]i64 = undefined;
    var job_ids: [contracts.release_order.len]i64 = undefined;
    for (contracts.release_order, 0..) |key, index| {
        const entry = support.objectOf(artifacts.get(key)) orelse return fail(
            diagnostic,
            "{s}: {s} artifact selection is missing",
            .{ key, @tagName(kind) },
        );
        if (!support.hasExactFields(entry, &.{
            "artifact_id",
            "artifact_name",
            "artifact_digest",
            "job_id",
            "job_name",
            "run_attempt",
        })) {
            return fail(
                diagnostic,
                "{s}: {s} artifact selection fields are not exact",
                .{ key, @tagName(kind) },
            );
        }
        artifact_ids[index] = positiveInteger(entry.get("artifact_id")) orelse
            return fail(
                diagnostic,
                "{s}: {s} artifact selection id is invalid",
                .{ key, @tagName(kind) },
            );
        job_ids[index] = positiveInteger(entry.get("job_id")) orelse return fail(
            diagnostic,
            "{s}: {s} job selection id is invalid",
            .{ key, @tagName(kind) },
        );
        const attempt = support.stringOf(entry.get("run_attempt")) orelse
            return fail(
                diagnostic,
                "{s}: {s} artifact selection attempt is invalid",
                .{ key, @tagName(kind) },
            );
        _ = positiveDecimal(attempt) orelse return fail(
            diagnostic,
            "{s}: {s} artifact selection attempt is invalid",
            .{ key, @tagName(kind) },
        );
        const expected_artifact = try std.fmt.allocPrint(
            allocator,
            "{s}-{s}-{s}-{s}",
            .{ kind.artifactPrefix(), key, source_commit, attempt },
        );
        defer allocator.free(expected_artifact);
        const expected_job = try expectedJobName(allocator, kind, key);
        defer allocator.free(expected_job);
        const digest = support.stringOf(entry.get("artifact_digest")) orelse "";
        if (!support.stringIs(entry.get("artifact_name"), expected_artifact) or
            !support.stringIs(entry.get("job_name"), expected_job) or
            !validArtifactDigest(digest))
        {
            return fail(
                diagnostic,
                "{s}: {s} artifact selection binding is invalid",
                .{ key, @tagName(kind) },
            );
        }
        for (0..index) |previous| {
            if (artifact_ids[previous] == artifact_ids[index] or
                job_ids[previous] == job_ids[index])
            {
                return fail(
                    diagnostic,
                    "{s} artifact selection contains duplicate identities",
                    .{@tagName(kind)},
                );
            }
        }
    }
    return parsed;
}

fn selectionAttempt(
    selection: std.json.Value,
    key: []const u8,
) []const u8 {
    return selection.object
        .get("artifacts").?
        .object
        .get(key).?
        .object
        .get("run_attempt").?
        .string;
}

/// The publish job's exact four-candidate gate.
pub fn releaseGate(
    allocator: Allocator,
    io: Io,
    options: ReleaseGateOptions,
    diagnostic: *Diagnostic,
) Error!void {
    if (!support.isCommit(options.source_commit) or
        positiveDecimal(options.candidate_run_id) == null or
        positiveDecimal(options.run_id) == null)
    {
        return fail(diagnostic, "release workflow identity is invalid", .{});
    }
    var candidate_selection = try loadArtifactSelection(
        allocator,
        io,
        options.candidate_selection,
        .candidate,
        options.candidate_run_id,
        options.source_commit,
        diagnostic,
    );
    defer candidate_selection.deinit();
    var native_selection = try loadArtifactSelection(
        allocator,
        io,
        options.native_selection,
        .native,
        options.run_id,
        options.source_commit,
        diagnostic,
    );
    defer native_selection.deinit();
    var azure_selection = try loadArtifactSelection(
        allocator,
        io,
        options.azure_selection,
        .azure,
        options.run_id,
        options.source_commit,
        diagnostic,
    );
    defer azure_selection.deinit();

    const candidate_paths = try collect(
        allocator,
        io,
        options.candidates,
        "candidate.json",
        diagnostic,
    );
    defer support.freePaths(allocator, candidate_paths);
    const native_paths = try collect(
        allocator,
        io,
        options.native_results,
        "native-result.json",
        diagnostic,
    );
    defer support.freePaths(allocator, native_paths);
    const azure_paths = try collect(
        allocator,
        io,
        options.azure_results,
        "azure-result.json",
        diagnostic,
    );
    defer support.freePaths(allocator, azure_paths);

    if (candidate_paths.len != contracts.release_order.len or
        native_paths.len != contracts.release_order.len or
        azure_paths.len != contracts.release_order.len)
    {
        return fail(
            diagnostic,
            "release gate did not receive four candidates, four native results, and four Azure results",
            .{},
        );
    }

    var candidate_index: [contracts.release_order.len]?usize = @splat(null);
    var candidate_values: [contracts.release_order.len]?std.json.Parsed(
        std.json.Value,
    ) = @splat(null);
    defer for (&candidate_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadReleaseByKey(
        allocator,
        io,
        candidate_paths,
        &candidate_index,
        &candidate_values,
        "unexpected or duplicate release candidate",
        "release candidate matrix is incomplete",
        diagnostic,
    );

    var native_index: [contracts.release_order.len]?usize = @splat(null);
    var native_values: [contracts.release_order.len]?std.json.Parsed(
        std.json.Value,
    ) = @splat(null);
    defer for (&native_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadReleaseByKey(
        allocator,
        io,
        native_paths,
        &native_index,
        &native_values,
        "unexpected or duplicate native result",
        "native validation matrix is incomplete",
        diagnostic,
    );
    try requireUniqueNativeDigests(
        &native_index,
        &native_values,
        "native validation matrix is incomplete",
        diagnostic,
    );

    var azure_index: [contracts.release_order.len]?usize = @splat(null);
    var azure_values: [contracts.release_order.len]?std.json.Parsed(
        std.json.Value,
    ) = @splat(null);
    defer for (&azure_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadReleaseByKey(
        allocator,
        io,
        azure_paths,
        &azure_index,
        &azure_values,
        "unexpected or duplicate Azure result",
        "Azure validation matrix is incomplete",
        diagnostic,
    );

    for (contracts.release_order, 0..) |key, index| {
        const candidate_position = candidate_index[index] orelse return fail(
            diagnostic,
            "release candidate matrix is incomplete",
            .{},
        );
        const manifest_path = candidate_paths[candidate_position];
        const manifest_parent = std.fs.path.dirname(manifest_path) orelse ".";
        const entry = contracts.lookup(key) orelse return fail(
            diagnostic,
            "unexpected release candidate identity",
            .{},
        );
        const asset_path = try support.joinPath(
            allocator,
            &.{ manifest_parent, entry.asset_name },
        );
        defer allocator.free(asset_path);

        var candidate = try documents.verifyCandidate(
            allocator,
            io,
            manifest_path,
            asset_path,
            key,
            options.source_commit,
            diagnostic,
        );
        defer candidate.deinit();
        try requireExactWorkflow(
            candidate.object().get("workflow"),
            options.candidate_run_id,
            selectionAttempt(candidate_selection.value, key),
            key,
            "candidate",
            diagnostic,
        );

        const native_position = native_index[index] orelse return fail(
            diagnostic,
            "native validation matrix is incomplete",
            .{},
        );
        var native = try documents.validateNativeResult(
            allocator,
            io,
            &candidate,
            native_paths[native_position],
            diagnostic,
        );
        defer native.deinit();
        try requireExactWorkflow(
            native.get("workflow"),
            options.run_id,
            selectionAttempt(native_selection.value, key),
            key,
            "native",
            diagnostic,
        );

        const azure_position = azure_index[index] orelse return fail(
            diagnostic,
            "Azure validation matrix is incomplete",
            .{},
        );
        var azure = try documents.validateAzureResult(
            allocator,
            io,
            &candidate,
            azure_paths[azure_position],
            diagnostic,
        );
        defer azure.deinit();
        try requireExactWorkflow(
            azure.get("workflow"),
            options.run_id,
            selectionAttempt(azure_selection.value, key),
            key,
            "Azure",
            diagnostic,
        );
    }
}

fn loadReleaseByKey(
    allocator: Allocator,
    io: Io,
    paths: []const []const u8,
    index: *[contracts.release_order.len]?usize,
    values: *[contracts.release_order.len]?std.json.Parsed(std.json.Value),
    duplicate_message: []const u8,
    incomplete_message: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    for (paths, 0..) |path, position| {
        var parsed = try readValue(allocator, io, path, diagnostic);
        errdefer parsed.deinit();
        const object = support.objectOf(parsed.value);
        const key = if (object) |value| support.stringOf(value.get("key")) else null;
        var slot: ?usize = null;
        if (key) |text| {
            for (contracts.release_order, 0..) |release_key, candidate_slot| {
                if (std.mem.eql(u8, release_key, text)) slot = candidate_slot;
            }
        }
        if (slot == null or index[slot.?] != null) {
            return fail(diagnostic, "{s}", .{duplicate_message});
        }
        index[slot.?] = position;
        values[position] = parsed;
    }
    for (index) |slot| {
        if (slot == null) return fail(diagnostic, "{s}", .{incomplete_message});
    }
}

pub fn requireExactWorkflow(
    value: ?std.json.Value,
    run_id: []const u8,
    run_attempt: []const u8,
    key: []const u8,
    kind: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const workflow = support.objectOf(value);
    if (workflow == null or
        !documents.hasWorkflowIdentity(value) or
        !support.stringIs(workflow.?.get("run_id"), run_id) or
        !support.stringIs(workflow.?.get("run_attempt"), run_attempt))
    {
        return fail(
            diagnostic,
            "{s}: {s} workflow attempt is not exact",
            .{ key, kind },
        );
    }
}

fn requireUniqueNativeDigests(
    index: anytype,
    values: anytype,
    incomplete_message: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var seen: [index.len][]const u8 = undefined;
    var seen_count: usize = 0;
    for (index) |position_value| {
        const position = position_value orelse return fail(
            diagnostic,
            "{s}",
            .{incomplete_message},
        );
        const parsed = values[position] orelse return fail(
            diagnostic,
            "{s}",
            .{incomplete_message},
        );
        const object = support.objectOf(parsed.value) orelse return fail(
            diagnostic,
            "malformed native acceptance result",
            .{},
        );
        const digest = try support.requireSha256(
            object.get("candidate_sha256"),
            "native candidate digest",
            diagnostic,
        );
        for (seen[0..seen_count]) |previous| {
            if (std.mem.eql(u8, previous, digest)) return fail(
                diagnostic,
                "duplicate native acceptance digest",
                .{},
            );
        }
        seen[seen_count] = digest;
        seen_count += 1;
    }
}

fn collect(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    filename: []const u8,
    diagnostic: *Diagnostic,
) Error![][]const u8 {
    const relative = support.listFilesNamed(
        allocator,
        io,
        root,
        filename,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot list {s}: {s}",
            .{ root, @errorName(err) },
        ),
    };
    defer support.freePaths(allocator, relative);
    var results: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit(allocator);
    }
    for (relative) |item| {
        try results.append(allocator, try support.joinPath(allocator, &.{ root, item }));
    }
    return results.toOwnedSlice(allocator);
}

pub const CoreGateOptions = struct {
    candidates: []const u8,
    native_results: []const u8,
    azure_results: []const u8,
    output: []const u8,
    source_commit: []const u8,
    candidate_run_id: []const u8,
    candidate_run_attempt: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
};

const core_keys = [_][]const u8{ "x86_64-core", "aarch64-core" };

/// The core-validation gate: two candidates, two native results, two Azure
/// results, and one digest-bound validation document recording them.
pub fn coreGate(
    allocator: Allocator,
    io: Io,
    options: CoreGateOptions,
    diagnostic: *Diagnostic,
) Error!void {
    const candidate_paths = try collect(
        allocator,
        io,
        options.candidates,
        "candidate.json",
        diagnostic,
    );
    defer support.freePaths(allocator, candidate_paths);
    const native_paths = try collect(
        allocator,
        io,
        options.native_results,
        "native-result.json",
        diagnostic,
    );
    defer support.freePaths(allocator, native_paths);
    const azure_paths = try collect(
        allocator,
        io,
        options.azure_results,
        "azure-result.json",
        diagnostic,
    );
    defer support.freePaths(allocator, azure_paths);
    const qcow_paths = support.listFilesWithSuffix(
        allocator,
        io,
        options.candidates,
        ".qcow2",
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "core gate did not receive two candidates, two native results, two Azure results, and two images",
            .{},
        ),
    };
    defer support.freePaths(allocator, qcow_paths);
    if (candidate_paths.len != 2 or native_paths.len != 2 or
        azure_paths.len != 2 or qcow_paths.len != 2)
    {
        return fail(
            diagnostic,
            "core gate did not receive two candidates, two native results, two Azure results, and two images",
            .{},
        );
    }

    var candidate_index: [2]?usize = .{ null, null };
    var candidate_values: [2]?std.json.Parsed(std.json.Value) = .{ null, null };
    defer for (&candidate_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadByKey(
        allocator,
        io,
        candidate_paths,
        &candidate_index,
        &candidate_values,
        "unexpected or duplicate core result",
        "core validation matrix is incomplete",
        diagnostic,
    );

    var azure_index: [2]?usize = .{ null, null };
    var azure_values: [2]?std.json.Parsed(std.json.Value) = .{ null, null };
    defer for (&azure_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadByKey(
        allocator,
        io,
        azure_paths,
        &azure_index,
        &azure_values,
        "unexpected or duplicate core result",
        "core validation matrix is incomplete",
        diagnostic,
    );

    var native_index: [2]?usize = .{ null, null };
    var native_values: [2]?std.json.Parsed(std.json.Value) = .{ null, null };
    defer for (&native_values) |*slot| {
        if (slot.*) |parsed| parsed.deinit();
    };
    try loadByKey(
        allocator,
        io,
        native_paths,
        &native_index,
        &native_values,
        "unexpected or duplicate native core result",
        "core native validation matrix is incomplete",
        diagnostic,
    );
    try requireUniqueNativeDigests(
        &native_index,
        &native_values,
        "core native validation matrix is incomplete",
        diagnostic,
    );

    var asset_seen: [2]bool = .{ false, false };
    for (qcow_paths) |path| {
        const name = std.fs.path.basename(path);
        for (core_keys, 0..) |key, slot| {
            if (std.mem.eql(u8, contracts.lookup(key).?.asset_name, name)) {
                asset_seen[slot] = true;
            }
        }
    }
    for (asset_seen) |seen| {
        if (!seen) return fail(
            diagnostic,
            "core candidate asset set is not exact",
            .{},
        );
    }

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());
    var records = builder.array();

    for (core_keys, 0..) |key, slot| {
        const entry = contracts.lookup(key).?;
        const manifest_path = candidate_paths[candidate_index[slot].?];
        const manifest_parent = std.fs.path.dirname(manifest_path) orelse ".";
        const asset_path = try support.joinPath(
            allocator,
            &.{ manifest_parent, entry.asset_name },
        );
        defer allocator.free(asset_path);

        var verified = try documents.verifyCandidate(
            allocator,
            io,
            manifest_path,
            asset_path,
            key,
            options.source_commit,
            diagnostic,
        );
        defer verified.deinit();

        const workflow_identity = support.objectOf(
            verified.object().get("workflow"),
        );
        if (workflow_identity == null or
            !support.stringIs(
                workflow_identity.?.get("run_id"),
                options.candidate_run_id,
            ) or
            !support.stringIs(
                workflow_identity.?.get("run_attempt"),
                options.candidate_run_attempt,
            ))
        {
            return fail(
                diagnostic,
                "{s}: candidate workflow attempt is not exact",
                .{key},
            );
        }

        const native_path = native_paths[native_index[slot].?];
        const native_result = &native_values[native_index[slot].?].?.value.object;
        if (!support.stringIs(
            native_result.get("candidate_sha256"),
            verified.sha256,
        )) {
            return fail(
                diagnostic,
                "{s}: native result is not candidate-key/digest bound",
                .{key},
            );
        }
        var native_document = try documents.validateNativeResult(
            allocator,
            io,
            &verified,
            native_path,
            diagnostic,
        );
        defer native_document.deinit();
        try requireExactWorkflow(
            native_document.get("workflow"),
            options.run_id,
            options.run_attempt,
            key,
            "native",
            diagnostic,
        );

        const azure_path = azure_paths[azure_index[slot].?];
        var azure_document = try documents.validateAzureResult(
            allocator,
            io,
            &verified,
            azure_path,
            diagnostic,
        );
        defer azure_document.deinit();

        const azure_workflow = support.objectOf(azure_document.get("workflow"));
        if (azure_workflow == null or
            !support.stringIs(azure_workflow.?.get("run_id"), options.run_id) or
            !support.stringIs(
                azure_workflow.?.get("run_attempt"),
                options.run_attempt,
            ))
        {
            return fail(
                diagnostic,
                "{s}: Azure workflow attempt is not exact",
                .{key},
            );
        }

        var record = builder.object();
        try builder.putString(&record, "key", key);
        try builder.putString(&record, "asset_name", entry.asset_name);
        try builder.putString(&record, "candidate_sha256", verified.sha256);
        try builder.putString(
            &record,
            "candidate_manifest_sha256",
            &(support.hashArtifact(io, manifest_path) catch return fail(
                diagnostic,
                "cannot read {s}",
                .{manifest_path},
            )).hex,
        );
        try builder.putString(
            &record,
            "native_result_sha256",
            &(support.hashArtifact(io, native_path) catch return fail(
                diagnostic,
                "cannot read {s}",
                .{native_path},
            )).hex,
        );
        try builder.putString(
            &record,
            "azure_result_sha256",
            &(support.hashArtifact(io, azure_path) catch return fail(
                diagnostic,
                "cannot read {s}",
                .{azure_path},
            )).hex,
        );
        try records.append(.{ .object = record });
    }

    var candidate_workflow = builder.object();
    try builder.putString(&candidate_workflow, "run_id", options.candidate_run_id);
    try builder.putString(
        &candidate_workflow,
        "run_attempt",
        options.candidate_run_attempt,
    );
    var validation_workflow = builder.object();
    try builder.putString(&validation_workflow, "run_id", options.run_id);
    try builder.putString(&validation_workflow, "run_attempt", options.run_attempt);

    var document = builder.object();
    try builder.putInteger(&document, "schema", 3);
    try builder.putString(&document, "type", "miz-ubuntu2604-core-validation");
    try builder.putString(&document, "source_commit", options.source_commit);
    try builder.put(
        &document,
        "candidate_workflow",
        .{ .object = candidate_workflow },
    );
    try builder.put(
        &document,
        "validation_workflow",
        .{ .object = validation_workflow },
    );
    try builder.put(&document, "candidates", .{ .array = records });
    try support.writeDocument(
        allocator,
        io,
        options.output,
        .{ .object = document },
        diagnostic,
    );
}

fn loadByKey(
    allocator: Allocator,
    io: Io,
    paths: []const []const u8,
    index: *[2]?usize,
    values: *[2]?std.json.Parsed(std.json.Value),
    duplicate_message: []const u8,
    incomplete_message: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    for (paths, 0..) |path, position| {
        var parsed = try readValue(allocator, io, path, diagnostic);
        errdefer parsed.deinit();
        const object = support.objectOf(parsed.value);
        const key = if (object) |value| support.stringOf(value.get("key")) else null;
        var slot: ?usize = null;
        if (key) |text| {
            for (core_keys, 0..) |core_key, candidate_slot| {
                if (std.mem.eql(u8, core_key, text)) slot = candidate_slot;
            }
        }
        if (slot == null or index[slot.?] != null) {
            return fail(diagnostic, "{s}", .{duplicate_message});
        }
        index[slot.?] = position;
        values[position] = parsed;
    }
    for (index) |slot| {
        if (slot == null) return fail(diagnostic, "{s}", .{incomplete_message});
    }
}

/// `KVM_GET_API_VERSION`. The stable ABI is 12; anything else means this
/// runner's `/dev/kvm` is not the interface the acceptance harness expects.
pub fn kvmApiVersion(
    io: Io,
    device: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const file = Dir.cwd().openFile(io, device, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = true,
    }) catch |err| return fail(
        diagnostic,
        "cannot open {s}: {s}",
        .{ device, @errorName(err) },
    );
    defer file.close(io);
    const result = std.os.linux.ioctl(file.handle, 0xAE00, 0);
    const errno = std.posix.errno(result);
    if (errno != .SUCCESS) return fail(
        diagnostic,
        "cannot query the KVM API version: {s}",
        .{@tagName(errno)},
    );
    if (result != 12) return fail(
        diagnostic,
        "unsupported KVM API version: {d}",
        .{result},
    );
}

/// The temporary resource group may only be deleted when its ownership tags
/// are exactly this run's.
pub fn azureCleanupTags(
    allocator: Allocator,
    io: Io,
    metadata_path: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    candidate_key: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var document = try support.readObject(allocator, io, metadata_path, diagnostic);
    defer document.deinit();
    const tags = support.objectOf(document.get("tags"));
    const expected = [_][2][]const u8{
        .{ "miz-owner", "ubuntu2604-release" },
        .{ "miz-run-id", run_id },
        .{ "miz-run-attempt", run_attempt },
        .{ "miz-candidate", candidate_key },
    };
    var matches = tags != null and tags.?.count() == expected.len;
    if (matches) {
        for (expected) |entry| {
            if (!support.stringIs(tags.?.get(entry[0]), entry[1])) matches = false;
        }
    }
    if (matches) return;

    const rendered = if (tags) |value| support.json_document.canonicalAlloc(
        allocator,
        .{ .object = value },
        .compact,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.OutOfMemory,
    } else try allocator.dupe(u8, "{}");
    defer allocator.free(rendered);
    return fail(
        diagnostic,
        "refusing to delete resource group with non-exact ownership tags: {s}",
        .{rendered},
    );
}

/// The configured VM SKU must exist, be unrestricted, match the architecture,
/// support Gen2 and Trusted Launch, and -- on x64 -- have a conventional
/// resource volume. The two output lines report whether that conventional
/// volume exists and whether either it or Azure local NVMe temporary storage
/// exists.
pub fn azureSku(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    sku_path: []const u8,
    vm_size: []const u8,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var parsed = try readValue(allocator, io, sku_path, diagnostic);
    defer parsed.deinit();
    const items = support.arrayOf(parsed.value) orelse return fail(
        diagnostic,
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    var match: ?std.json.ObjectMap = null;
    var matches: usize = 0;
    for (items) |item| {
        const entry = support.objectOf(item) orelse continue;
        if (!support.stringIs(entry.get("name"), vm_size)) continue;
        matches += 1;
        match = entry;
    }
    if (matches != 1) return fail(
        diagnostic,
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    const sku = match.?;

    var restrictions: std.json.Array = .init(allocator);
    defer restrictions.deinit();
    if (support.arrayOf(sku.get("restrictions"))) |listed| {
        for (listed) |restriction| {
            const entry = support.objectOf(restriction) orelse continue;
            if (!support.stringIs(entry.get("type"), "Location")) continue;
            try restrictions.append(restriction);
        }
    }
    if (restrictions.items.len != 0) {
        const rendered = support.json_document.canonicalAlloc(
            allocator,
            .{ .array = restrictions },
            .compact,
        ) catch return error.OutOfMemory;
        defer allocator.free(rendered);
        return fail(
            diagnostic,
            "configured Azure VM SKU is location-restricted: {s}",
            .{rendered},
        );
    }

    var cpu_architecture: []const u8 = "";
    var hyper_v: []const u8 = "";
    var trusted_launch_disabled: []const u8 = "";
    var resource_volume: []const u8 = "0";
    var nvme_volume: []const u8 = "0";
    var cpu_architecture_count: usize = 0;
    var hyper_v_count: usize = 0;
    var trusted_launch_count: usize = 0;
    var resource_volume_count: usize = 0;
    var nvme_volume_count: usize = 0;
    if (support.arrayOf(sku.get("capabilities"))) |capabilities| {
        for (capabilities) |capability| {
            const entry = support.objectOf(capability) orelse continue;
            const name = support.stringOf(entry.get("name")) orelse continue;
            if (std.mem.eql(u8, name, "CpuArchitectureType")) {
                const value = support.stringOf(entry.get("value")) orelse
                    return fail(
                        diagnostic,
                        "configured Azure VM SKU has malformed capabilities",
                        .{},
                    );
                cpu_architecture = value;
                cpu_architecture_count += 1;
            } else if (std.mem.eql(u8, name, "HyperVGenerations")) {
                const value = support.stringOf(entry.get("value")) orelse
                    return fail(
                        diagnostic,
                        "configured Azure VM SKU has malformed capabilities",
                        .{},
                    );
                hyper_v = value;
                hyper_v_count += 1;
            } else if (std.mem.eql(u8, name, "TrustedLaunchDisabled")) {
                const value = support.stringOf(entry.get("value")) orelse
                    return fail(
                        diagnostic,
                        "configured Azure VM SKU has malformed capabilities",
                        .{},
                    );
                trusted_launch_disabled = value;
                trusted_launch_count += 1;
            } else if (std.mem.eql(u8, name, "MaxResourceVolumeMB")) {
                const value = support.stringOf(entry.get("value")) orelse
                    return fail(
                        diagnostic,
                        "configured Azure VM SKU has malformed capabilities",
                        .{},
                    );
                resource_volume = value;
                resource_volume_count += 1;
            } else if (std.mem.eql(u8, name, "NvmeDiskSizeInMiB")) {
                const value = support.stringOf(entry.get("value")) orelse
                    return fail(
                        diagnostic,
                        "configured Azure VM SKU has malformed capabilities",
                        .{},
                    );
                nvme_volume = value;
                nvme_volume_count += 1;
            }
        }
    }
    if (cpu_architecture_count > 1 or hyper_v_count > 1 or
        trusted_launch_count > 1 or resource_volume_count > 1 or
        nvme_volume_count > 1)
    {
        return fail(
            diagnostic,
            "configured Azure VM SKU has ambiguous capabilities",
            .{},
        );
    }
    if (!std.mem.eql(u8, cpu_architecture, architecture)) {
        if (cpu_architecture_count != 0) return fail(
            diagnostic,
            "SKU architecture mismatch: '{s}'",
            .{cpu_architecture},
        );
        return fail(diagnostic, "SKU architecture mismatch: None", .{});
    }
    var generations = std.mem.splitScalar(u8, hyper_v, ',');
    var has_gen2 = false;
    while (generations.next()) |generation| {
        if (std.mem.eql(u8, generation, "V2")) has_gen2 = true;
    }
    if (!has_gen2) return fail(
        diagnostic,
        "configured Azure VM SKU does not support Gen2",
        .{},
    );
    if (trusted_launch_count != 0 and
        !std.mem.eql(u8, trusted_launch_disabled, "True") and
        !std.mem.eql(u8, trusted_launch_disabled, "False"))
    {
        return fail(
            diagnostic,
            "configured Azure VM SKU reports an invalid Trusted Launch capability",
            .{},
        );
    }
    if (std.mem.eql(u8, trusted_launch_disabled, "True")) return fail(
        diagnostic,
        "configured Azure VM SKU does not support Trusted Launch",
        .{},
    );
    const volume = std.fmt.parseInt(i64, resource_volume, 10) catch return fail(
        diagnostic,
        "configured Azure VM SKU reports an invalid resource volume size",
        .{},
    );
    if (volume < 0) return fail(
        diagnostic,
        "configured Azure VM SKU reports an invalid resource volume size",
        .{},
    );
    const nvme = std.fmt.parseInt(i64, nvme_volume, 10) catch return fail(
        diagnostic,
        "configured Azure VM SKU reports an invalid local NVMe size",
        .{},
    );
    if (nvme < 0) return fail(
        diagnostic,
        "configured Azure VM SKU reports an invalid local NVMe size",
        .{},
    );
    const has_conventional_resource_disk = volume > 0;
    const has_local_temp_storage = has_conventional_resource_disk or nvme > 0;
    if (std.mem.eql(u8, architecture, "x64") and
        !has_conventional_resource_disk)
    {
        return fail(
            diagnostic,
            "configured Azure VM SKU has no temporary resource disk",
            .{},
        );
    }
    try out.print("{s}\n{s}\n", .{
        if (has_conventional_resource_disk) "true" else "false",
        if (has_local_temp_storage) "true" else "false",
    });
}

pub const ConversionOptions = struct {
    output: []const u8,
    key: []const u8,
    asset_name: []const u8,
    qcow_sha256: []const u8,
    qcow_bytes: i64,
    virtual_size: i64,
    vhd_sha256: []const u8,
    vhd_bytes: i64,
    vhd_current_size: i64,
    info: []const u8,
};

/// The harness-side attestation that binds `miz azure derive`'s inputs to the
/// VHD that was actually produced.
pub fn conversionAttestation(
    allocator: Allocator,
    io: Io,
    options: ConversionOptions,
    diagnostic: *Diagnostic,
) Error!void {
    var info_document = try support.readObject(
        allocator,
        io,
        options.info,
        diagnostic,
    );
    defer info_document.deinit();
    const qemu_virtual_size = support.integerOf(
        info_document.get("virtual-size"),
    ) orelse return fail(
        diagnostic,
        "qemu-img omitted the derived VHD virtual size",
        .{},
    );
    const info_digest = support.hashArtifact(io, options.info) catch return fail(
        diagnostic,
        "cannot read {s}",
        .{options.info},
    );

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());

    var source = builder.object();
    try builder.putString(&source, "asset_name", options.asset_name);
    try builder.putString(&source, "sha256_before", options.qcow_sha256);
    try builder.putString(&source, "sha256_after", options.qcow_sha256);
    try builder.putInteger(&source, "bytes", options.qcow_bytes);
    try builder.putInteger(&source, "virtual_size", options.virtual_size);

    var parameters = builder.object();
    try builder.putString(&parameters, "input_sha256", options.qcow_sha256);
    try builder.putInteger(
        &parameters,
        "expected_virtual_size",
        options.virtual_size,
    );
    try builder.putString(&parameters, "output_format", "vpc-fixed");
    try builder.putInteger(&parameters, "vhd_alignment_bytes", 1024 * 1024);
    try builder.putInteger(&parameters, "vhd_footer_bytes", 512);

    var result = builder.object();
    try builder.putString(&result, "sha256", options.vhd_sha256);
    try builder.putInteger(&result, "bytes", options.vhd_bytes);
    try builder.putInteger(&result, "current_size", options.vhd_current_size);
    try builder.putInteger(&result, "qemu_virtual_size", qemu_virtual_size);
    try builder.putString(&result, "qemu_info_sha256", &info_digest.hex);

    var document = builder.object();
    try builder.putInteger(&document, "schema", 1);
    try builder.putString(&document, "type", "miz-azure-vhd-conversion");
    try builder.putString(&document, "key", options.key);
    try builder.putString(&document, "status", "success");
    try builder.putString(&document, "tool", "miz");
    try builder.putString(&document, "operation", "azure derive");
    try builder.put(&document, "source", .{ .object = source });
    try builder.put(&document, "parameters", .{ .object = parameters });
    try builder.put(&document, "result", .{ .object = result });

    return support.writeDocument(
        allocator,
        io,
        options.output,
        .{ .object = document },
        diagnostic,
    );
}

/// The gallery image-version request that enrolls the release signer in the
/// image's custom UEFI db.
pub fn galleryRequest(
    allocator: Allocator,
    io: Io,
    output: []const u8,
    location: []const u8,
    disk_id: []const u8,
    certificate_path: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const certificate = support.file_support.readBounded(
        allocator,
        io,
        certificate_path,
        support.document_max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read {s}: {s}",
            .{ certificate_path, @errorName(err) },
        ),
    };
    defer allocator.free(certificate);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());
    const encoder = std.base64.standard.Encoder;
    const encoded = try arena.allocator().alloc(
        u8,
        encoder.calcSize(certificate.len),
    );
    _ = encoder.encode(encoded, certificate);

    var region = builder.object();
    try builder.putString(&region, "name", location);
    try builder.putInteger(&region, "regionalReplicaCount", 1);
    try builder.putString(&region, "storageAccountType", "Standard_LRS");
    var regions = builder.array();
    try regions.append(.{ .object = region });

    var publishing = builder.object();
    try builder.putString(&publishing, "replicationMode", "Shallow");
    try builder.put(&publishing, "targetRegions", .{ .array = regions });

    var source = builder.object();
    try builder.putString(&source, "id", disk_id);
    var os_disk_image = builder.object();
    try builder.put(&os_disk_image, "source", .{ .object = source });
    var storage = builder.object();
    try builder.put(&storage, "osDiskImage", .{ .object = os_disk_image });

    var certificate_values = builder.array();
    try certificate_values.append(.{ .string = encoded });
    var signature = builder.object();
    try builder.putString(&signature, "type", "x509");
    try builder.put(&signature, "value", .{ .array = certificate_values });
    var db = builder.array();
    try db.append(.{ .object = signature });
    var additional = builder.object();
    try builder.put(&additional, "db", .{ .array = db });

    var uefi = builder.object();
    try builder.put(&uefi, "signatureTemplateNames", try builder.strings(
        &.{"MicrosoftUefiCertificateAuthorityTemplate"},
    ));
    try builder.put(&uefi, "additionalSignatures", .{ .object = additional });
    var security = builder.object();
    try builder.put(&security, "uefiSettings", .{ .object = uefi });

    var properties = builder.object();
    try builder.put(&properties, "publishingProfile", .{ .object = publishing });
    try builder.put(&properties, "storageProfile", .{ .object = storage });
    try builder.put(&properties, "securityProfile", .{ .object = security });

    var payload = builder.object();
    try builder.putString(&payload, "location", location);
    try builder.put(&payload, "properties", .{ .object = properties });

    return support.writeDocument(
        allocator,
        io,
        output,
        .{ .object = payload },
        diagnostic,
    );
}

/// The final gallery image-version check, after provisioning completed.
pub fn galleryVerify(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    request_path: []const u8,
    response_path: []const u8,
    image_version_id: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var request_document = try support.readObject(
        allocator,
        io,
        request_path,
        diagnostic,
    );
    defer request_document.deinit();
    var response_document = try support.readObject(
        allocator,
        io,
        response_path,
        diagnostic,
    );
    defer response_document.deinit();

    const identity = support.stringOf(response_document.get("id")) orelse "";
    if (!std.ascii.eqlIgnoreCase(identity, image_version_id)) return fail(
        diagnostic,
        "Azure returned a different gallery image-version identity",
        .{},
    );
    const expected = try requestUefiSettings(request_document.object(), diagnostic);
    const actual = documents.galleryUefiSettings(response_document.object());
    if (actual != null and !support.jsonEqual(actual.?, expected)) return fail(
        diagnostic,
        "Azure returned different custom UEFI settings after provisioning",
        .{},
    );
    if (actual == null) {
        try out.writeAll(
            "Azure omitted custom UEFI settings from the final GET; boot validation remains authoritative\n",
        );
    }
    const properties = support.objectOf(response_document.get("properties"));
    const state = if (properties) |object|
        support.stringOf(object.get("provisioningState"))
    else
        null;
    if (state == null or !std.mem.eql(u8, state.?, "Succeeded")) {
        if (state) |text| return fail(
            diagnostic,
            "gallery image-version provisioning did not succeed: '{s}'",
            .{text},
        );
        return fail(
            diagnostic,
            "gallery image-version provisioning did not succeed: None",
            .{},
        );
    }
}

const efi_cert_x509_guid = [16]u8{
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
};

/// Walks the EFI signature lists read out of the guest's `db` variable and
/// requires the release signer to be enrolled as an X.509 certificate.
pub fn uefiDb(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const text = support.file_support.readBounded(
        allocator,
        io,
        path,
        support.document_max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer allocator.free(text);

    // The report comes from the static guest probe rather than from a
    // `mount -t efivarfs` plus `cat`: `mount` is util-linux, and issue #677
    // forbids the image keeping a package because acceptance used it.
    const line = (runtime_contract.efivarLine(
        text,
        runtime_contract.signature_database_variable,
    ) catch return fail(
        diagnostic,
        "{s}: the UEFI variable report is unparseable",
        .{path},
    )) orelse return fail(
        diagnostic,
        "{s}: the UEFI variable report never mentions {s}",
        .{ path, runtime_contract.signature_database_variable },
    );
    if (line.status != .ok) return fail(
        diagnostic,
        "{s}: UEFI db is {s}",
        .{ path, line.status.key() },
    );
    if (!std.mem.eql(u8, line.filesystem, runtime_contract.efivars_filesystem)) return fail(
        diagnostic,
        "{s}: UEFI db was read through {s}, not {s}",
        .{ path, line.filesystem, runtime_contract.efivars_filesystem },
    );
    // A `db` without time-based authenticated write access is a signature
    // database anyone could rewrite, which is not a trust anchor.
    if (!line.hasAttributes(runtime_contract.signature_database_attributes)) return fail(
        diagnostic,
        "{s}: UEFI db attributes are 0x{x:0>8}",
        .{ path, line.attributes },
    );

    const data = try allocator.alloc(u8, line.data_hex.len / 2);
    defer allocator.free(data);
    _ = line.decode(data) catch return fail(
        diagnostic,
        "{s}: UEFI db data is not a byte string",
        .{path},
    );

    var offset: usize = 0;
    var found = false;
    while (offset < data.len) {
        if (data.len - offset < 28) return fail(
            diagnostic,
            "truncated EFI signature list",
            .{},
        );
        const list_size = std.mem.readInt(u32, data[offset + 16 ..][0..4], .little);
        const header_size = std.mem.readInt(u32, data[offset + 20 ..][0..4], .little);
        const signature_size = std.mem.readInt(
            u32,
            data[offset + 24 ..][0..4],
            .little,
        );
        const is_x509 = std.mem.eql(u8, data[offset..][0..16], &efi_cert_x509_guid);
        if (list_size < 28 or signature_size <= 16) return fail(
            diagnostic,
            "invalid EFI signature list",
            .{},
        );
        const end = std.math.add(usize, offset, list_size) catch return fail(
            diagnostic,
            "invalid EFI signature-list bounds",
            .{},
        );
        const signatures_start = std.math.add(
            usize,
            offset + 28,
            header_size,
        ) catch return fail(
            diagnostic,
            "invalid EFI signature-list bounds",
            .{},
        );
        if (end > data.len or signatures_start > end or
            (end - signatures_start) % signature_size != 0)
        {
            return fail(diagnostic, "invalid EFI signature-list bounds", .{});
        }
        var signatures = signatures_start;
        while (signatures < end) : (signatures += signature_size) {
            const certificate = data[signatures + 16 .. signatures + signature_size];
            if (is_x509 and std.mem.eql(
                u8,
                &support.digest.hexBytes(certificate),
                certificate_sha256,
            )) {
                found = true;
            }
        }
        offset = end;
    }
    if (!found) return fail(
        diagnostic,
        "release signing certificate is absent from UEFI db",
        .{},
    );
}

/// Prints the required `status` field of a JSON document read from standard
/// input.
pub fn statusFromStdin(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    diagnostic: *Diagnostic,
) OutError!void {
    var buffer: [64 * 1024]u8 = undefined;
    var reader: File.Reader = .init(.stdin(), io, &buffer);
    const bytes = reader.interface.allocRemaining(
        allocator,
        .limited(support.document_max_bytes),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(diagnostic, "cannot read the status document", .{}),
    };
    defer allocator.free(bytes);

    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(diagnostic, "status document is malformed", .{}),
    };
    defer parsed.deinit();

    const object = support.objectOf(parsed.value);
    const status = if (object) |value|
        support.stringOf(value.get("status"))
    else
        null;
    if (status == null) return fail(
        diagnostic,
        "status document does not carry a status",
        .{},
    );
    try out.print("{s}\n", .{status.?});
}

/// One line of the publication allowlist: name, digest, and size.
const Expected = struct {
    text: []u8,
    entries: std.ArrayListUnmanaged(Entry),

    const Entry = struct {
        name: []const u8,
        sha256: []const u8,
        bytes: u64,
    };

    fn deinit(self: *Expected, allocator: Allocator) void {
        self.entries.deinit(allocator);
        allocator.free(self.text);
        self.* = undefined;
    }

    fn findIndex(self: *const Expected, name: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.name, name)) return index;
        }
        return null;
    }

    fn find(self: *const Expected, name: []const u8) ?Entry {
        const index = self.findIndex(name) orelse return null;
        return self.entries.items[index];
    }
};

fn readExpected(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!Expected {
    const text = support.file_support.readBounded(
        allocator,
        io,
        path,
        support.document_max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    errdefer allocator.free(text);
    var entries: std.ArrayListUnmanaged(Expected.Entry) = .empty;
    errdefer entries.deinit(allocator);

    var rest: []const u8 = text;
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..end];
        rest = if (end == rest.len) rest[end..] else rest[end + 1 ..];
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, '\t');
        const name = parts.next() orelse return fail(
            diagnostic,
            "publication allowlist line is malformed",
            .{},
        );
        const sha256 = parts.next() orelse return fail(
            diagnostic,
            "publication allowlist line is malformed",
            .{},
        );
        const size = parts.next() orelse return fail(
            diagnostic,
            "publication allowlist line is malformed",
            .{},
        );
        if (parts.next() != null) return fail(
            diagnostic,
            "publication allowlist line is malformed",
            .{},
        );
        try entries.append(allocator, .{
            .name = name,
            .sha256 = sha256,
            .bytes = std.fmt.parseInt(u64, size, 10) catch return fail(
                diagnostic,
                "publication allowlist line is malformed",
                .{},
            ),
        });
        // The allowlist is the identity of the publication: a repeated name
        // would make "exactly these assets" ambiguous, so it is rejected here
        // rather than silently collapsed by a later lookup.
        for (entries.items[0 .. entries.items.len - 1]) |earlier| {
            if (std.mem.eql(u8, earlier.name, name)) return fail(
                diagnostic,
                "publication allowlist line is malformed",
                .{},
            );
        }
    }
    return .{ .text = text, .entries = entries };
}

/// The publication allowlist: exactly the four published assets, and nothing
/// else staged next to them.
pub fn publishExpected(
    allocator: Allocator,
    io: Io,
    out: *Writer,
    manifest_path: []const u8,
    assets_root: []const u8,
    release_tag: []const u8,
    source_commit: []const u8,
    diagnostic: *Diagnostic,
) OutError!void {
    var document = try support.readObject(allocator, io, manifest_path, diagnostic);
    defer document.deinit();
    const manifest = document.object();
    if (!support.hasExactFields(manifest.*, &.{
        "schema",
        "type",
        "release_tag",
        "source_commit",
        "certificate_sha256",
        "signing_certificate_sha256",
        "signing_provider",
        "publication_workflow",
        "assets",
    }) or
        support.integerOf(manifest.get("schema")) != 2 or
        !support.stringIs(manifest.get("type"), "miz-ubuntu2604-release") or
        !documents.hasWorkflowIdentity(manifest.get("publication_workflow")))
    {
        return fail(diagnostic, "unexpected Ubuntu publish manifest schema", .{});
    }
    if (!support.stringIs(manifest.get("release_tag"), release_tag)) return fail(
        diagnostic,
        "publish manifest release tag mismatch",
        .{},
    );
    if (!support.stringIs(manifest.get("source_commit"), source_commit)) return fail(
        diagnostic,
        "publish manifest source commit mismatch",
        .{},
    );
    const assets = support.arrayOf(manifest.get("assets"));
    if (assets == null or assets.?.len != contracts.release_order.len) return fail(
        diagnostic,
        "Ubuntu publication allowlist mismatch",
        .{},
    );
    var seen: [contracts.release_order.len]bool = @splat(false);
    for (assets.?) |asset| {
        const entry = support.objectOf(asset) orelse return fail(
            diagnostic,
            "Ubuntu publication allowlist mismatch",
            .{},
        );
        if (!support.hasExactFields(entry, &.{
            "key",
            "architecture",
            "flavor",
            "asset_name",
            "sha256",
            "bytes",
            "virtual_size",
            "build_runner",
            "provenance_digest",
            "certificate_sha256",
            "signing_certificate_sha256",
            "fallback_uki_sha256",
            "candidate_workflow",
            "native_workflow",
            "azure_workflow",
            "azure_location",
            "azure_vm_size",
            "azure_resource_group",
            "conversion",
            "derived_vhd_sha256",
            "derived_vhd_bytes",
            "derived_vhd_current_size",
            "azure_image_version_id",
        }) or
            !documents.hasWorkflowIdentity(entry.get("candidate_workflow")) or
            !documents.hasWorkflowIdentity(entry.get("native_workflow")) or
            !documents.hasWorkflowIdentity(entry.get("azure_workflow")))
        {
            return fail(
                diagnostic,
                "Ubuntu publication provenance is not exact",
                .{},
            );
        }
        const key = support.stringOf(entry.get("key")) orelse return fail(
            diagnostic,
            "Ubuntu publication allowlist mismatch",
            .{},
        );
        var index: ?usize = null;
        for (contracts.release_order, 0..) |release_key, position| {
            if (std.mem.eql(u8, release_key, key)) index = position;
        }
        if (index == null or seen[index.?]) return fail(
            diagnostic,
            "Ubuntu publication allowlist mismatch",
            .{},
        );
        if (!support.stringIs(
            entry.get("asset_name"),
            contracts.lookup(key).?.asset_name,
        )) {
            return fail(diagnostic, "Ubuntu publication allowlist mismatch", .{});
        }
        seen[index.?] = true;
    }

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(allocator);
    for (assets.?) |asset| {
        const entry = support.objectOf(asset).?;
        const name = support.stringOf(entry.get("asset_name"));
        const sha256 = support.stringOf(entry.get("sha256"));
        const size = support.integerOf(entry.get("bytes"));
        if (name == null or
            !std.mem.eql(u8, std.fs.path.basename(name.?), name.?) or
            sha256 == null or !support.isSha256(sha256.?) or
            size == null or size.? <= 0)
        {
            return fail(diagnostic, "invalid Ubuntu publish manifest asset", .{});
        }
        for (names.items) |seen_name| {
            if (std.mem.eql(u8, seen_name, name.?)) return fail(
                diagnostic,
                "invalid Ubuntu publish manifest asset",
                .{},
            );
        }
        try names.append(allocator, name.?);
        try out.print("{s}\t{s}\t{d}\n", .{ name.?, sha256.?, size.? });
    }

    var directory = Dir.cwd().openDir(io, assets_root, .{ .iterate = true }) catch
        return fail(
            diagnostic,
            "staged release allowlist mismatch: cannot list {s}",
            .{assets_root},
        );
    defer directory.close(io);
    var iterator = directory.iterate();
    var actual: usize = 0;
    while (iterator.next(io) catch return fail(
        diagnostic,
        "staged release allowlist mismatch: cannot list {s}",
        .{assets_root},
    )) |item| {
        // `readdir`'s kind is a hint: a symlinked asset is a file to
        // `is_file()`, and a filesystem may report every entry as unknown.
        if (!support.entryIsFile(io, directory, item.name)) continue;
        actual += 1;
        if (std.mem.eql(u8, item.name, "publish-manifest.json")) continue;
        var known = false;
        for (names.items) |name| {
            if (std.mem.eql(u8, name, item.name)) known = true;
        }
        if (!known) return fail(
            diagnostic,
            "staged release allowlist mismatch: {s}",
            .{item.name},
        );
    }
    if (actual != names.items.len + 1) return fail(
        diagnostic,
        "staged release allowlist mismatch: {d} staged files",
        .{actual},
    );
}

/// The remote release must carry exactly the allowlisted assets, at the right
/// sizes, in the right draft state for the publication stage.
pub fn releaseAssets(
    allocator: Allocator,
    io: Io,
    release_path: []const u8,
    expected_path: []const u8,
    stage: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const final = if (std.mem.eql(u8, stage, "final"))
        true
    else if (std.mem.eql(u8, stage, "draft"))
        false
    else
        return fail(
            diagnostic,
            "unknown publication stage: {s}",
            .{stage},
        );

    var expected = try readExpected(allocator, io, expected_path, diagnostic);
    defer expected.deinit(allocator);
    var document = try support.readObject(allocator, io, release_path, diagnostic);
    defer document.deinit();

    // Every rejection below is the stage's single diagnostic, because the
    // Python compared whole dictionaries and reported one mismatch either way.
    const mismatch = struct {
        fn report(
            final_stage: bool,
            count: usize,
            report_diagnostic: *Diagnostic,
        ) Error {
            if (final_stage) return fail(
                report_diagnostic,
                "published release did not retain the exact final allowlist",
                .{},
            );
            return fail(
                report_diagnostic,
                "remote release asset allowlist/size mismatch: {d} assets",
                .{count},
            );
        }
    }.report;

    const assets = support.arrayOf(document.get("assets")) orelse
        return mismatch(final, 0, diagnostic);
    const draft = support.isTrue(document.get("draft"));
    if (final and draft) return mismatch(true, assets.len, diagnostic);
    if (assets.len != expected.entries.items.len) {
        return mismatch(final, assets.len, diagnostic);
    }

    // Cardinality alone would accept the same asset listed twice while a
    // required one is absent, so each remote asset must claim a distinct
    // allowlist entry and every entry must end up claimed.
    const claimed = allocator.alloc(bool, expected.entries.items.len) catch
        return error.OutOfMemory;
    defer allocator.free(claimed);
    @memset(claimed, false);

    for (assets) |asset| {
        const entry = support.objectOf(asset) orelse
            return mismatch(final, assets.len, diagnostic);
        const name = support.stringOf(entry.get("name")) orelse
            return mismatch(final, assets.len, diagnostic);
        const index = expected.findIndex(name) orelse
            return mismatch(final, assets.len, diagnostic);
        if (claimed[index]) return mismatch(final, assets.len, diagnostic);
        claimed[index] = true;
        const size = support.integerOf(entry.get("size")) orelse
            return mismatch(final, assets.len, diagnostic);
        if (size < 0 or
            @as(u64, @intCast(size)) != expected.entries.items[index].bytes)
        {
            return mismatch(final, assets.len, diagnostic);
        }
    }
    for (claimed) |taken| {
        if (!taken) return mismatch(final, assets.len, diagnostic);
    }

    if (!final and !draft) return fail(
        diagnostic,
        "release stopped being a draft before verification",
        .{},
    );
}

/// The downloaded copy of the release must be byte-identical to the staged
/// assets: the only proof that what is published is what was validated.
pub fn releaseDownloaded(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    expected_path: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var expected = try readExpected(allocator, io, expected_path, diagnostic);
    defer expected.deinit(allocator);

    var directory = Dir.cwd().openDir(io, root, .{ .iterate = true }) catch
        return fail(
            diagnostic,
            "downloaded release allowlist mismatch: cannot list {s}",
            .{root},
        );
    defer directory.close(io);
    var iterator = directory.iterate();
    var actual: usize = 0;
    while (iterator.next(io) catch return fail(
        diagnostic,
        "downloaded release allowlist mismatch: cannot list {s}",
        .{root},
    )) |item| {
        if (!support.entryIsFile(io, directory, item.name)) continue;
        actual += 1;
        if (expected.find(item.name) == null) return fail(
            diagnostic,
            "downloaded release allowlist mismatch: {s}",
            .{item.name},
        );
    }
    if (actual != expected.entries.items.len) return fail(
        diagnostic,
        "downloaded release allowlist mismatch: {d} files",
        .{actual},
    );

    for (expected.entries.items) |entry| {
        const path = try support.joinPath(allocator, &.{ root, entry.name });
        defer allocator.free(path);
        const digest = support.hashArtifact(io, path) catch return fail(
            diagnostic,
            "{s}: downloaded size mismatch",
            .{entry.name},
        );
        if (digest.size != entry.bytes) return fail(
            diagnostic,
            "{s}: downloaded size mismatch",
            .{entry.name},
        );
        if (!std.mem.eql(u8, &digest.hex, entry.sha256)) return fail(
            diagnostic,
            "{s}: downloaded digest mismatch",
            .{entry.name},
        );
    }
}

test "Python truthiness decides whether a backing filename is present" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"empty": "", "set": "base.qcow2", "nothing": null, "zero": 0}
    ,
        .{},
    );
    defer parsed.deinit();
    const object = &parsed.value.object;
    try std.testing.expect(!isTruthy(object.get("empty")));
    try std.testing.expect(isTruthy(object.get("set")));
    try std.testing.expect(!isTruthy(object.get("nothing")));
    try std.testing.expect(!isTruthy(object.get("zero")));
    try std.testing.expect(!isTruthy(object.get("absent")));
}

test "nestedObject walks only through objects" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"format-specific": {"data": {"compression-type": "zstd"}},
        \\ "flat": {"data": 3}}
    ,
        .{},
    );
    defer parsed.deinit();
    const data = nestedObject(parsed.value, &.{ "format-specific", "data" }).?;
    try std.testing.expect(support.stringIs(data.get("compression-type"), "zstd"));
    try std.testing.expect(nestedObject(parsed.value, &.{ "flat", "data" }) == null);
    try std.testing.expect(nestedObject(parsed.value, &.{"absent"}) == null);
}
