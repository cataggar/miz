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
const documents = @import("documents.zig");
const download = @import("download.zig");
const provenance = @import("provenance.zig");
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
    if (std.mem.eql(u8, command, "release-gate")) {
        var options = try parse(allocator, argv, &.{
            "--candidates",
            "--native-results",
            "--azure-results",
            "--source-commit",
            "--candidate-run-id",
            "--candidate-run-attempt",
            "--run-id",
            "--run-attempt",
        });
        defer options.deinit();
        return releaseGate(allocator, io, .{
            .candidates = try options.require("--candidates"),
            .native_results = try options.require("--native-results"),
            .azure_results = try options.require("--azure-results"),
            .source_commit = try options.require("--source-commit"),
            .candidate_run_id = try options.require("--candidate-run-id"),
            .candidate_run_attempt = try options.require("--candidate-run-attempt"),
            .run_id = try options.require("--run-id"),
            .run_attempt = try options.require("--run-attempt"),
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
            "--db",
            "--certificate-sha256",
        });
        defer options.deinit();
        return uefiDb(
            allocator,
            io,
            try options.require("--db"),
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

pub const ReleaseGateOptions = struct {
    candidates: []const u8,
    native_results: []const u8,
    azure_results: []const u8,
    source_commit: []const u8,
    candidate_run_id: []const u8,
    candidate_run_attempt: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
};

/// The publish job's exact four-candidate gate.
pub fn releaseGate(
    allocator: Allocator,
    io: Io,
    options: ReleaseGateOptions,
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
            options.candidate_run_attempt,
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
            options.run_attempt,
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
            options.run_attempt,
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

fn requireExactWorkflow(
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
/// support Gen2 and Trusted Launch, and -- on x64 -- have a resource disk.
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
    var has_cpu_architecture = false;
    if (support.arrayOf(sku.get("capabilities"))) |capabilities| {
        for (capabilities) |capability| {
            const entry = support.objectOf(capability) orelse continue;
            const name = support.stringOf(entry.get("name")) orelse continue;
            const value = support.stringOf(entry.get("value")) orelse continue;
            if (std.mem.eql(u8, name, "CpuArchitectureType")) {
                cpu_architecture = value;
                has_cpu_architecture = true;
            } else if (std.mem.eql(u8, name, "HyperVGenerations")) {
                hyper_v = value;
            } else if (std.mem.eql(u8, name, "TrustedLaunchDisabled")) {
                trusted_launch_disabled = value;
            } else if (std.mem.eql(u8, name, "MaxResourceVolumeMB")) {
                resource_volume = value;
            }
        }
    }
    if (!std.mem.eql(u8, cpu_architecture, architecture)) {
        if (has_cpu_architecture) return fail(
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
    const has_resource_disk = volume > 0;
    if (std.mem.eql(u8, architecture, "x64") and !has_resource_disk) return fail(
        diagnostic,
        "configured Azure VM SKU has no temporary resource disk",
        .{},
    );
    try out.print("{s}\n", .{if (has_resource_disk) "true" else "false"});
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
    const data = support.file_support.readBounded(
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
    defer allocator.free(data);

    // The first four bytes are the variable's attributes, not signature data.
    var offset: usize = 4;
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
    if (support.integerOf(manifest.get("schema")) != 1 or
        !support.stringIs(manifest.get("type"), "miz-ubuntu2604-release"))
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
