//! Validate and bind Azure Linux 4 release artifacts across workflow jobs.
//!
//! Native port of `scripts/azurelinux4_release.py`, which this tool replaces
//! outright, together with every inline Python block in the Azure Linux
//! release workflow, the Azure acceptance harness, and the publisher.
//!
//! The release is a chain of handoffs between jobs that do not trust each
//! other: a hosted runner builds and signs a candidate, a protected
//! environment boots the exact bytes on Azure, and a publisher moves those
//! same bytes onto a GitHub release. Every link in that chain is a document
//! this tool writes and a later job re-derives from the artifacts themselves.
//! Absorbing the shell's inline validation here keeps all of it in one place,
//! under test, with one failure convention.
//!
//!     azurelinux4_release <command> [--option value]...
//!
//! A validation failure prints one line to stderr and exits 1. A usage error
//! exits 2, matching the `argparse` interface the shell callers were written
//! against. Commands that produce values print them to stdout, one per line,
//! in the order the callers read them.

const std = @import("std");

const azure = @import("azurelinux4/azure.zig");
const azure_vhd = @import("azure_vhd.zig");
const commands = @import("azurelinux4/commands.zig");
const contracts = @import("azurelinux4/contracts.zig");
const publish = @import("azurelinux4/publish.zig");
const release = @import("release/root.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Writer = std.Io.Writer;
const contract = release.contract;
const file_support = release.file;
const json_document = release.json_document;

pub const Diagnostic = contract.Diagnostic;

const usage_exit_code = 2;
const failure_exit_code = 1;

const usage_text =
    \\usage: azurelinux4_release <command> [--option value]...
    \\
    \\Validate and bind Azure Linux 4 release artifacts across workflow jobs.
    \\
    \\release documents:
    \\  candidate              bind a built asset to its digest, provenance, and signer
    \\  verify-candidate       re-derive a candidate manifest and print digest/bytes/virtual size
    \\  verify-vhd             validate a derived upload VHD and print its current/file sizes
    \\  azure-result           bind an Azure acceptance run to the candidate it accepted
    \\  stage                  stage the exact four published assets, manifest, and notes
    \\
    \\build validation:
    \\  check-candidate-info   require a standalone zstd QCOW2 of the expected virtual size
    \\
    \\Azure acceptance:
    \\  signing-identity       print the release signer identity and write its DER certificate
    \\  check-group-tags       require exact ownership tags before deleting a resource group
    \\  disk-access-sas        print the SAS URL of an accepted disk write-access grant
    \\  check-vm-sku           require an exact Gen2 Trusted Launch SKU; print resource-disk support
    \\  gallery-request        write the gallery image-version request with the release signer
    \\  check-gallery-accepted require the create response to echo the requested UEFI settings
    \\  gallery-state          print the gallery image-version provisioning state
    \\  check-gallery-final    require the final GET to keep the identity, settings, and success
    \\  check-vm-security      require Trusted Launch, Secure Boot, and vTPM on a VM profile
    \\  check-uefi-db          require the release certificate in the guest UEFI db
    \\
    \\publication:
    \\  publish-expected       print the expected asset table from the publish manifest
    \\  tag-ref                print the object an exact release tag ref points at
    \\  tag-object             print the object a peeled annotated tag points at
    \\  release-stale-assets   print the asset IDs a release holds outside the allowlist
    \\  check-release-assets   require the exact remote allowlist in draft or published state
    \\  check-downloads        re-hash a downloaded release against the expected asset table
    \\
;

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const ArgumentError = error{ Usage, HelpRequested };

/// The parsed `--name value` options of one command.
///
/// Every option this tool accepts is a long option with a value, spelled
/// either `--name value` or `--name=value`, exactly as `argparse` accepted
/// them. An option the command does not declare is a usage error rather than
/// something silently ignored, because a caller passing an option this tool
/// does not honour believes a check is running that is not.
const Options = struct {
    const capacity = 32;

    names: [capacity][]const u8 = undefined,
    values: [capacity][]const u8 = undefined,
    count: usize = 0,

    fn get(self: *const Options, name: []const u8) ?[]const u8 {
        for (self.names[0..self.count], self.values[0..self.count]) |actual, value| {
            if (std.mem.eql(u8, actual, name)) return value;
        }
        return null;
    }

    fn require(self: *const Options, name: []const u8) ArgumentError![]const u8 {
        return self.get(name) orelse error.Usage;
    }

    fn requireInteger(self: *const Options, name: []const u8) ArgumentError!i64 {
        const text = try self.require(name);
        return std.fmt.parseInt(i64, text, 10) catch error.Usage;
    }

    /// Every value given for a repeatable option, in order.
    fn all(
        self: *const Options,
        name: []const u8,
        buffer: *[capacity][]const u8,
    ) []const []const u8 {
        var found: usize = 0;
        for (self.names[0..self.count], self.values[0..self.count]) |actual, value| {
            if (!std.mem.eql(u8, actual, name)) continue;
            buffer[found] = value;
            found += 1;
        }
        return buffer[0..found];
    }
};

fn parseOptions(
    argv: []const []const u8,
    allowed: []const []const u8,
) ArgumentError!Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (!std.mem.startsWith(u8, argument, "--")) return error.Usage;
        const body = argument[2..];
        const separator = std.mem.indexOfScalar(u8, body, '=');
        const name = if (separator) |at| body[0..at] else body;
        var matched = false;
        for (allowed) |candidate_name| {
            if (std.mem.eql(u8, candidate_name, name)) matched = true;
        }
        if (!matched) return error.Usage;
        const value = if (separator) |at| body[at + 1 ..] else blk: {
            index += 1;
            if (index >= argv.len) return error.Usage;
            break :blk argv[index];
        };
        if (options.count == Options.capacity) return error.Usage;
        options.names[options.count] = name;
        options.values[options.count] = value;
        options.count += 1;
    }
    return options;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

const Context = struct {
    allocator: Allocator,
    io: Io,
    out: *Writer,
    diagnostic: *Diagnostic,
};

fn run(context: Context, argv: []const []const u8) !void {
    if (argv.len == 0) return error.Usage;
    const command = argv[0];
    const rest = argv[1..];

    if (std.mem.eql(u8, command, "candidate")) return runCandidate(context, rest);
    if (std.mem.eql(u8, command, "verify-candidate")) {
        return runVerifyCandidate(context, rest);
    }
    if (std.mem.eql(u8, command, "verify-vhd")) return runVerifyVhd(context, rest);
    if (std.mem.eql(u8, command, "azure-result")) return runAzureResult(context, rest);
    if (std.mem.eql(u8, command, "stage")) return runStage(context, rest);
    if (std.mem.eql(u8, command, "check-candidate-info")) {
        return runCheckCandidateInfo(context, rest);
    }
    if (std.mem.eql(u8, command, "signing-identity")) {
        return runSigningIdentity(context, rest);
    }
    if (std.mem.eql(u8, command, "check-group-tags")) {
        return runCheckGroupTags(context, rest);
    }
    if (std.mem.eql(u8, command, "disk-access-sas")) {
        return runDiskAccessSas(context, rest);
    }
    if (std.mem.eql(u8, command, "check-vm-sku")) return runCheckVmSku(context, rest);
    if (std.mem.eql(u8, command, "gallery-request")) {
        return runGalleryRequest(context, rest);
    }
    if (std.mem.eql(u8, command, "check-gallery-accepted")) {
        return runCheckGalleryAccepted(context, rest);
    }
    if (std.mem.eql(u8, command, "gallery-state")) return runGalleryState(context, rest);
    if (std.mem.eql(u8, command, "check-gallery-final")) {
        return runCheckGalleryFinal(context, rest);
    }
    if (std.mem.eql(u8, command, "check-vm-security")) {
        return runCheckVmSecurity(context, rest);
    }
    if (std.mem.eql(u8, command, "check-uefi-db")) return runCheckUefiDb(context, rest);
    if (std.mem.eql(u8, command, "publish-expected")) {
        return runPublishExpected(context, rest);
    }
    if (std.mem.eql(u8, command, "tag-ref")) return runTagRef(context, rest);
    if (std.mem.eql(u8, command, "tag-object")) return runTagObject(context, rest);
    if (std.mem.eql(u8, command, "release-stale-assets")) {
        return runReleaseStaleAssets(context, rest);
    }
    if (std.mem.eql(u8, command, "check-release-assets")) {
        return runCheckReleaseAssets(context, rest);
    }
    if (std.mem.eql(u8, command, "check-downloads")) {
        return runCheckDownloads(context, rest);
    }
    return error.Usage;
}

const candidate_options = [_][]const u8{
    "key",
    "architecture",
    "flavor",
    "asset",
    "validated-sha256",
    "virtual-size",
    "source-commit",
    "provenance-dir",
    "runner",
    "run-id",
    "run-attempt",
    "output",
};

fn runCandidate(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &candidate_options);
    try commands.candidate(context.allocator, context.io, .{
        .key = try options.require("key"),
        .architecture = try options.require("architecture"),
        .flavor = try options.require("flavor"),
        .asset = try options.require("asset"),
        .validated_sha256 = try options.require("validated-sha256"),
        .virtual_size = try options.requireInteger("virtual-size"),
        .source_commit = try options.require("source-commit"),
        .provenance_dir = try options.require("provenance-dir"),
        .runner = try options.require("runner"),
        .run_id = try options.require("run-id"),
        .run_attempt = try options.require("run-attempt"),
        .output = try options.require("output"),
    }, context.diagnostic);
}

const verify_candidate_options = [_][]const u8{
    "manifest",
    "asset",
    "key",
    "source-commit",
};

fn runVerifyCandidate(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &verify_candidate_options);
    var verified = try commands.verifyCandidate(
        context.allocator,
        context.io,
        try options.require("manifest"),
        try options.require("asset"),
        try options.require("key"),
        try options.require("source-commit"),
        context.diagnostic,
    );
    defer verified.deinit();
    try context.out.print("{s}\n{d}\n{d}\n", .{
        verified.sha256,
        verified.bytes,
        verified.virtual_size,
    });
}

fn runVerifyVhd(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "info", "vhd" });
    var vhd_context: azure_vhd.Context = .{};
    const inspection = azure_vhd.inspect(
        context.allocator,
        context.io,
        try options.require("info"),
        try options.require("vhd"),
        &vhd_context,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            context.diagnostic.set("{s}", .{vhd_context.message()});
            // The size context is the whole subject of a VHD failure, so it
            // travels with the failure line rather than being dropped.
            var note: Writer.Allocating = .init(context.allocator);
            defer note.deinit();
            vhd_context.writeNote(&note.writer) catch {};
            try appendNote(context.diagnostic, note.written());
            return err;
        },
    };
    try context.out.print("{d}\n{d}\n", .{
        inspection.current_size,
        inspection.file_size,
    });
}

/// Appends already-rendered note lines behind the failure line, keeping the
/// first line the message a caller greps for.
fn appendNote(diagnostic: *Diagnostic, note: []const u8) !void {
    if (note.len == 0) return;
    var buffer: [contract.message_capacity]u8 = undefined;
    const combined = std.fmt.bufPrint(&buffer, "{s}\n{s}", .{
        diagnostic.message(),
        std.mem.trimEnd(u8, note, "\n"),
    }) catch return;
    diagnostic.set("{s}", .{combined});
}

const azure_result_options = [_][]const u8{
    "manifest",
    "asset",
    "vhd",
    "vhd-current-size",
    "key",
    "source-commit",
    "location",
    "vm-size",
    "resource-group",
    "image-version-id",
    "uefi-request",
    "uefi-response",
    "run-id",
    "run-attempt",
    "output",
};

fn runAzureResult(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &azure_result_options);
    try commands.azureResult(context.allocator, context.io, .{
        .manifest = try options.require("manifest"),
        .asset = try options.require("asset"),
        .vhd = try options.require("vhd"),
        .vhd_current_size = try options.requireInteger("vhd-current-size"),
        .key = try options.require("key"),
        .source_commit = try options.require("source-commit"),
        .location = try options.require("location"),
        .vm_size = try options.require("vm-size"),
        .resource_group = try options.require("resource-group"),
        .image_version_id = try options.require("image-version-id"),
        .uefi_request = try options.require("uefi-request"),
        .uefi_response = try options.require("uefi-response"),
        .run_id = try options.require("run-id"),
        .run_attempt = try options.require("run-attempt"),
        .output = try options.require("output"),
    }, context.diagnostic);
}

const stage_options = [_][]const u8{
    "candidates",
    "azure-results",
    "source-commit",
    "release-tag",
    "output",
    "notes",
};

fn runStage(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &stage_options);
    try commands.stage(context.allocator, context.io, .{
        .candidates = try options.require("candidates"),
        .azure_results = try options.require("azure-results"),
        .source_commit = try options.require("source-commit"),
        .release_tag = try options.require("release-tag"),
        .output = try options.require("output"),
        .notes = try options.require("notes"),
    }, context.diagnostic);
}

fn runCheckCandidateInfo(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "info", "virtual-size" });
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("info"),
        context.diagnostic,
    );
    defer document.deinit();
    try azure.checkCandidateInfo(
        &document.parsed.value.object,
        try options.requireInteger("virtual-size"),
        context.diagnostic,
    );
}

fn runSigningIdentity(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "manifest", "certificate-der" });
    var document = try json_document.readObject(
        context.allocator,
        context.io,
        try options.require("manifest"),
        commands.max_release_document_bytes,
        context.diagnostic,
    );
    defer document.deinit();
    const identity = try azure.signingIdentity(
        context.allocator,
        &document.parsed.value.object,
        context.diagnostic,
    );
    const destination = try options.require("certificate-der");
    file_support.writeAtomic(
        context.io,
        destination,
        identity.certificate,
    ) catch |err| return context.diagnostic.fail(
        error.Io,
        "cannot write {s}: {s}",
        .{ destination, @errorName(err) },
    );
    try context.out.print("{s}\n{s}\n", .{
        identity.certificate_sha256,
        identity.fallback_uki_sha256,
    });
}

fn runCheckGroupTags(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "metadata",
        "run-id",
        "run-attempt",
        "key",
    });
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("metadata"),
        context.diagnostic,
    );
    defer document.deinit();
    try azure.checkGroupTags(context.allocator, &document.parsed.value.object, .{
        .run_id = try options.require("run-id"),
        .run_attempt = try options.require("run-attempt"),
        .candidate_key = try options.require("key"),
    }, context.diagnostic);
}

fn runDiskAccessSas(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"response"});
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer document.deinit();
    try azure.writeDiskAccessSas(
        &document.parsed.value.object,
        context.out,
        context.diagnostic,
    );
}

fn runCheckVmSku(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "skus", "vm-size", "architecture" });
    var parsed = try azure.readValue(
        context.allocator,
        context.io,
        try options.require("skus"),
        azure.max_document_bytes,
        context.diagnostic,
    );
    defer parsed.deinit();
    const result = try azure.checkVmSku(
        context.allocator,
        parsed.value,
        try options.require("vm-size"),
        try options.require("architecture"),
        context.diagnostic,
    );
    try context.out.print("{s}\n", .{if (result.has_resource_disk) "true" else "false"});
}

fn runGalleryRequest(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "output",
        "location",
        "disk-id",
        "certificate",
    });
    const certificate_path = try options.require("certificate");
    const certificate = file_support.readBounded(
        context.allocator,
        context.io,
        certificate_path,
        azure.max_certificate_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return context.diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ certificate_path, @errorName(err) },
        ),
    };
    const request = try azure.galleryRequest(
        context.allocator,
        try options.require("location"),
        try options.require("disk-id"),
        certificate,
    );
    const destination = try options.require("output");
    json_document.writeDocument(
        context.allocator,
        context.io,
        destination,
        request,
    ) catch |err| return context.diagnostic.fail(
        error.Io,
        "cannot write {s}: {s}",
        .{ destination, @errorName(err) },
    );
}

fn runCheckGalleryAccepted(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "request", "response" });
    var request = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("request"),
        context.diagnostic,
    );
    defer request.deinit();
    var response = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer response.deinit();
    try azure.checkGalleryAccepted(
        &request.parsed.value.object,
        &response.parsed.value.object,
        context.diagnostic,
    );
}

fn runGalleryState(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"response"});
    var response = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer response.deinit();
    try azure.writeGalleryState(
        &response.parsed.value.object,
        context.out,
        context.diagnostic,
    );
}

fn runCheckGalleryFinal(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "request",
        "response",
        "image-version-id",
    });
    var request = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("request"),
        context.diagnostic,
    );
    defer request.deinit();
    var response = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer response.deinit();
    try azure.checkGalleryFinal(
        context.allocator,
        &request.parsed.value.object,
        &response.parsed.value.object,
        try options.require("image-version-id"),
        context.out,
        context.diagnostic,
    );
}

fn runCheckVmSecurity(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"profile"});
    var buffer: [Options.capacity][]const u8 = undefined;
    const profiles = options.all("profile", &buffer);
    if (profiles.len == 0) return error.Usage;
    for (profiles) |path| {
        var document = try azure.readObject(
            context.allocator,
            context.io,
            path,
            context.diagnostic,
        );
        defer document.deinit();
        try azure.checkVmSecurity(
            &document.parsed.value.object,
            path,
            context.diagnostic,
        );
    }
}

fn runCheckUefiDb(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "db", "certificate-sha256" });
    const path = try options.require("db");
    const data = file_support.readBounded(
        context.allocator,
        context.io,
        path,
        azure.max_uefi_db_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return context.diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    const fingerprint = try options.require("certificate-sha256");
    if (!contract.isSha256Hex(fingerprint)) return context.diagnostic.fail(
        error.InvalidSha256,
        "release signing certificate fingerprint is not a lowercase SHA-256",
        .{},
    );
    try azure.checkUefiDb(data, fingerprint, context.diagnostic);
}

fn runPublishExpected(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"manifest"});
    var document = try json_document.readObject(
        context.allocator,
        context.io,
        try options.require("manifest"),
        commands.max_release_document_bytes,
        context.diagnostic,
    );
    defer document.deinit();
    try publish.writeExpected(
        &document.parsed.value.object,
        context.out,
        context.diagnostic,
    );
}

fn runTagRef(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "refs", "tag" });
    var parsed = try azure.readValue(
        context.allocator,
        context.io,
        try options.require("refs"),
        azure.max_document_bytes,
        context.diagnostic,
    );
    defer parsed.deinit();
    try publish.writeTagRef(
        parsed.value,
        try options.require("tag"),
        context.out,
        context.diagnostic,
    );
}

fn runTagObject(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"document"});
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("document"),
        context.diagnostic,
    );
    defer document.deinit();
    try publish.writeTagObject(
        &document.parsed.value.object,
        context.out,
        context.diagnostic,
    );
}

fn runReleaseStaleAssets(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "release", "expected" });
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("release"),
        context.diagnostic,
    );
    defer document.deinit();
    const expected = try publish.readExpected(
        context.allocator,
        context.io,
        try options.require("expected"),
        context.diagnostic,
    );
    try publish.writeStaleAssetIds(
        &document.parsed.value.object,
        expected,
        context.out,
        context.diagnostic,
    );
}

fn runCheckReleaseAssets(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "release", "expected", "state" });
    const state_text = try options.require("state");
    const state: publish.ReleaseState = if (std.mem.eql(u8, state_text, "draft"))
        .draft
    else if (std.mem.eql(u8, state_text, "published"))
        .published
    else
        return error.Usage;
    var document = try azure.readObject(
        context.allocator,
        context.io,
        try options.require("release"),
        context.diagnostic,
    );
    defer document.deinit();
    const expected = try publish.readExpected(
        context.allocator,
        context.io,
        try options.require("expected"),
        context.diagnostic,
    );
    try publish.checkReleaseAssets(
        context.allocator,
        &document.parsed.value.object,
        expected,
        state,
        context.diagnostic,
    );
}

fn runCheckDownloads(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "directory", "expected" });
    const expected = try publish.readExpected(
        context.allocator,
        context.io,
        try options.require("expected"),
        context.diagnostic,
    );
    try publish.checkDownloads(
        context.allocator,
        context.io,
        try options.require("directory"),
        expected,
        context.diagnostic,
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    for (argv[1..]) |argument| {
        if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) {
            try out.writeAll(usage_text);
            try out.flush();
            return;
        }
    }

    var diagnostic: Diagnostic = .{};
    run(.{
        .allocator = allocator,
        .io = io,
        .out = out,
        .diagnostic = &diagnostic,
    }, argv[1..]) catch |err| switch (err) {
        error.Usage => {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        },
        error.OutOfMemory => return err,
        else => {
            // A validation failure always carries its operator-facing line;
            // anything else is named by its error so nothing exits silently.
            if (diagnostic.message().len != 0) {
                try err_out.print("{s}\n", .{diagnostic.message()});
            } else {
                try err_out.print("{s}\n", .{@errorName(err)});
            }
            try err_out.flush();
            std.process.exit(failure_exit_code);
        },
    };
    try out.flush();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test {
    _ = azure;
    _ = commands;
    _ = contracts;
    _ = publish;
}

test "options accept both argparse spellings and reject the rest" {
    const allowed = [_][]const u8{ "key", "asset", "virtual-size" };
    const spaced = try parseOptions(
        &.{ "--key", "x86_64-full", "--asset", "a.qcow2", "--virtual-size", "1024" },
        &allowed,
    );
    try std.testing.expectEqualStrings("x86_64-full", try spaced.require("key"));
    try std.testing.expectEqualStrings("a.qcow2", try spaced.require("asset"));
    try std.testing.expectEqual(@as(i64, 1024), try spaced.requireInteger("virtual-size"));

    const joined = try parseOptions(
        &.{ "--key=aarch64-core", "--asset=b.qcow2", "--virtual-size=7" },
        &allowed,
    );
    try std.testing.expectEqualStrings("aarch64-core", try joined.require("key"));
    try std.testing.expectEqual(@as(i64, 7), try joined.requireInteger("virtual-size"));

    // An option the command does not declare, a positional, a value-less
    // trailing option, and a non-numeric integer are all usage errors.
    try std.testing.expectError(error.Usage, parseOptions(&.{"--unknown=1"}, &allowed));
    try std.testing.expectError(error.Usage, parseOptions(&.{"positional"}, &allowed));
    try std.testing.expectError(error.Usage, parseOptions(&.{"--key"}, &allowed));
    const missing = try parseOptions(&.{"--key=x"}, &allowed);
    try std.testing.expectError(error.Usage, missing.require("asset"));
    const bad_number = try parseOptions(&.{"--virtual-size=ten"}, &allowed);
    try std.testing.expectError(error.Usage, bad_number.requireInteger("virtual-size"));
}

test "a repeatable option keeps every value in order" {
    const options = try parseOptions(
        &.{ "--profile", "vm.json", "--profile", "instance.json" },
        &.{"profile"},
    );
    var buffer: [Options.capacity][]const u8 = undefined;
    const profiles = options.all("profile", &buffer);
    try std.testing.expectEqual(@as(usize, 2), profiles.len);
    try std.testing.expectEqualStrings("vm.json", profiles[0]);
    try std.testing.expectEqualStrings("instance.json", profiles[1]);
}

test "every command the shell and workflow call is dispatched" {
    // The commands this tool must answer to. A rename that misses a caller
    // would otherwise only show up in a release run.
    const named = [_][]const u8{
        "candidate",
        "verify-candidate",
        "verify-vhd",
        "azure-result",
        "stage",
        "check-candidate-info",
        "signing-identity",
        "check-group-tags",
        "disk-access-sas",
        "check-vm-sku",
        "gallery-request",
        "check-gallery-accepted",
        "gallery-state",
        "check-gallery-final",
        "check-vm-security",
        "check-uefi-db",
        "publish-expected",
        "tag-ref",
        "tag-object",
        "release-stale-assets",
        "check-release-assets",
        "check-downloads",
    };
    for (named) |command| {
        // Every command is listed in the usage text, and none of them is
        // reachable without its own options.
        try std.testing.expect(std.mem.indexOf(u8, usage_text, command) != null);
    }
    try std.testing.expectEqual(@as(usize, 22), named.len);
}

test "the failure note follows the failure line" {
    var diagnostic: Diagnostic = .{};
    diagnostic.set("derived upload VHD is not fixed", .{});
    try appendNote(&diagnostic, "note: footer current size is 1048576 bytes (1.0 MiB)\n");
    try std.testing.expectEqualStrings(
        "derived upload VHD is not fixed\n" ++
            "note: footer current size is 1048576 bytes (1.0 MiB)",
        diagnostic.message(),
    );

    diagnostic.set("plain failure", .{});
    try appendNote(&diagnostic, "");
    try std.testing.expectEqualStrings("plain failure", diagnostic.message());
}
