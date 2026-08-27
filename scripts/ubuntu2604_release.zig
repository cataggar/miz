//! Validate and bind Ubuntu 26.04 release artifacts across workflow jobs.
//!
//! Native port of `scripts/ubuntu2604_release.py`. Every command contract the
//! release, core-validation, acceptance, and publication callers depend on is
//! preserved: the same subcommand names and options, the same stdout lines,
//! the same one-line failure text on stderr, exit 1 for a validation failure,
//! and exit 2 for a usage error.
//!
//! The tool also absorbs the inline Python those callers used to embed. Those
//! checks were always domain logic -- "is this the exact image the build
//! validated", "did Azure return the settings we asked for", "is this release
//! carrying exactly the two published assets" -- and they belong next to the
//! schemas they check rather than inside a shell heredoc.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
// Re-exported so the behavioral test suite can drive the same code the
// subcommands do, rather than a parallel copy of it.
pub const azure_vhd = @import("azure_vhd.zig");
pub const cli = @import("ubuntu2604/cli.zig");
pub const commands = @import("ubuntu2604/commands.zig");
pub const contracts = @import("ubuntu2604/contracts.zig");
pub const documents = @import("ubuntu2604/documents.zig");
pub const android = @import("ubuntu2604/android.zig");
pub const archive = @import("ubuntu2604/archive.zig");
pub const keys = @import("ubuntu2604/keys.zig");
pub const provenance = @import("ubuntu2604/provenance.zig");
pub const support = @import("ubuntu2604/support.zig");
pub const workflow = @import("ubuntu2604/workflow.zig");

const Diagnostic = support.Diagnostic;
const Error = support.Error;

const usage_exit_code = 2;
const failure_exit_code = 1;

const usage_text =
    \\usage: ubuntu2604_release COMMAND [OPTIONS]
    \\
    \\Validate and bind Ubuntu 26.04 release artifacts across workflow jobs.
    \\
    \\commands:
    \\  prepare-android-smoke-inputs  fetch and verify the external Android
    \\                                container smoke inputs
    \\  candidate                     bind a built QCOW2 to its provenance tree
    \\  verify-candidate              re-verify a candidate against its asset
    \\  verify-native-result          verify native acceptance against a candidate
    \\  verify-native-evidence        verify a native result against a manifest
    \\  verify-vhd                    validate a derived upload VHD
    \\  azure-contracts               print the Azure contracts for a flavor
    \\  azure-result                  record an Azure acceptance result
    \\  verify-azure-result           re-verify an Azure acceptance result
    \\  stage                         stage the exact published asset set
    \\  verify-image-info             check a miz image-info document
    \\  candidate-signing-env         export the candidate signing bindings
    \\  release-gate                  check the two-architecture release gate
    \\  core-gate                     check and record the core validation gate
    \\  kvm-api-version               check the host KVM API version
    \\  azure-cleanup-tags            check temporary resource-group ownership
    \\  azure-disk-access             print a disk write-access SAS URL
    \\  azure-boot-artifact           download a bounded boot diagnostic
    \\  azure-failure-diagnostics     write the failure diagnostics document
    \\  azure-sku                     check the VM SKU and report its resource disk
    \\  azure-conversion-attestation  write the VHD conversion attestation
    \\  azure-gallery-request         write the gallery image-version request
    \\  azure-gallery-accepted        check the create response UEFI settings
    \\  azure-gallery-state           print the gallery provisioning state
    \\  azure-gallery-verify          check the final gallery image-version
    \\  azure-vm-security             check Trusted Launch, Secure Boot, and vTPM
    \\  azure-uefi-db                 check the signer is enrolled in UEFI db
    \\  android-bundle-config         check the Android bundle config mounts
    \\  android-container-status      print a container status read from stdin
    \\  cloud-init-status             print the cloud-init status read from stdin
    \\  publish-expected              print the expected published asset table
    \\  github-tag-object             print the tag ref object identity
    \\  github-tag-target             print a tag object's target identity
    \\  github-stale-assets           print release assets outside the allowlist
    \\  github-release-assets         check remote release assets
    \\  github-release-downloaded     check downloaded release assets
    \\
;

const Context = struct {
    allocator: Allocator,
    io: Io,
    out: *std.Io.Writer,
    diagnostic: Diagnostic = .{},
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [64 * 1024]u8 = undefined;
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
    if (argv.len < 2) {
        try err_out.writeAll(usage_text);
        try err_out.flush();
        std.process.exit(usage_exit_code);
    }

    var context: Context = .{ .allocator = allocator, .io = io, .out = out };
    dispatch(&context, argv[1], argv[2..], init) catch |err| switch (err) {
        error.Usage => {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        },
        error.Failed => {
            try err_out.print("{s}\n", .{context.diagnostic.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        },
        else => return err,
    };
    try out.flush();
}

fn dispatch(
    context: *Context,
    command: []const u8,
    argv: []const []const u8,
    init: std.process.Init,
) !void {
    const allocator = context.allocator;
    const io = context.io;
    const diagnostic = &context.diagnostic;

    if (std.mem.eql(u8, command, "prepare-android-smoke-inputs")) {
        var options = try cli.parse(allocator, argv, &.{
            "--architecture",
            "--output-dir",
            "--github-env",
        });
        defer options.deinit();
        const architecture = try options.require("--architecture");
        if (contracts.parseArchitecture(architecture) == null) return error.Usage;
        // The secret and the bearer token are read here and nowhere else, and
        // they never leave this call.
        const secret = std.process.Environ.getAlloc(
            init.minimal.environ,
            allocator,
            android.input_env,
        ) catch null;
        defer if (secret) |value| allocator.free(value);
        const token_value = std.process.Environ.getAlloc(
            init.minimal.environ,
            allocator,
            android.token_env,
        ) catch null;
        defer if (token_value) |value| allocator.free(value);
        return android.prepare(allocator, io, .{
            .architecture = architecture,
            .output_dir = try options.require("--output-dir"),
            .github_env = try options.require("--github-env"),
            .secret = secret,
            .token = if (token_value) |value|
                (if (value.len == 0) null else value)
            else
                null,
        }, diagnostic);
    }

    if (std.mem.eql(u8, command, "candidate")) {
        var options = try cli.parse(allocator, argv, &.{
            "--key",
            "--architecture",
            "--flavor",
            "--asset",
            "--validated-sha256",
            "--virtual-size",
            "--source-commit",
            "--provenance-dir",
            "--runner",
            "--run-id",
            "--run-attempt",
            "--output",
        });
        defer options.deinit();
        return commands.candidate(allocator, io, .{
            .key = try options.require("--key"),
            .architecture = try options.require("--architecture"),
            .flavor = try options.require("--flavor"),
            .asset = try options.require("--asset"),
            .validated_sha256 = try options.require("--validated-sha256"),
            .virtual_size = try options.requireInteger("--virtual-size"),
            .source_commit = try options.require("--source-commit"),
            .provenance_dir = try options.require("--provenance-dir"),
            .runner = try options.require("--runner"),
            .run_id = try options.require("--run-id"),
            .run_attempt = try options.require("--run-attempt"),
            .output = try options.require("--output"),
        }, diagnostic);
    }

    if (std.mem.eql(u8, command, "verify-candidate")) {
        var options = try cli.parse(allocator, argv, &.{
            "--manifest",
            "--asset",
            "--key",
            "--source-commit",
        });
        defer options.deinit();
        var verified = try documents.verifyCandidate(
            allocator,
            io,
            try options.require("--manifest"),
            try options.require("--asset"),
            try options.require("--key"),
            try options.require("--source-commit"),
            diagnostic,
        );
        defer verified.deinit();
        try context.out.print("{s}\n{d}\n{d}\n", .{
            verified.sha256,
            verified.bytes,
            verified.virtual_size,
        });
        return;
    }

    if (std.mem.eql(u8, command, "verify-native-result")) {
        var options = try cli.parse(allocator, argv, &.{
            "--manifest",
            "--asset",
            "--result",
            "--key",
            "--source-commit",
        });
        defer options.deinit();
        var verified = try documents.verifyCandidate(
            allocator,
            io,
            try options.require("--manifest"),
            try options.require("--asset"),
            try options.require("--key"),
            try options.require("--source-commit"),
            diagnostic,
        );
        defer verified.deinit();
        var result = try documents.validateNativeResult(
            allocator,
            io,
            &verified,
            try options.require("--result"),
            diagnostic,
        );
        defer result.deinit();
        try context.out.print("{s}\n", .{
            support.stringOf(result.get("candidate_sha256")).?,
        });
        try writeJoined(context.out, support.arrayOf(result.get("contracts")).?);
        return;
    }

    if (std.mem.eql(u8, command, "verify-vhd")) {
        var options = try cli.parse(allocator, argv, &.{ "--info", "--vhd" });
        defer options.deinit();
        var vhd_context: azure_vhd.Context = .{};
        const inspection = azure_vhd.inspect(
            allocator,
            io,
            try options.require("--info"),
            try options.require("--vhd"),
            &vhd_context,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                diagnostic.set("{s}", .{vhd_context.message()});
                return error.Failed;
            },
        };
        try context.out.print("{d}\n{d}\n", .{
            inspection.current_size,
            inspection.file_size,
        });
        return;
    }

    if (std.mem.eql(u8, command, "azure-contracts")) {
        var options = try cli.parse(allocator, argv, &.{"--flavor"});
        defer options.deinit();
        const flavor = contracts.parseFlavor(try options.require("--flavor")) orelse
            return error.Usage;
        const list = contracts.azureContracts(flavor);
        for (list, 0..) |item, index| {
            if (index != 0) try context.out.writeAll(",");
            try context.out.writeAll(item);
        }
        try context.out.writeAll("\n");
        return;
    }

    if (std.mem.eql(u8, command, "azure-result")) {
        var options = try cli.parse(allocator, argv, &.{
            "--manifest",
            "--asset",
            "--vhd",
            "--vhd-info",
            "--conversion-attestation",
            "--key",
            "--source-commit",
            "--location",
            "--vm-size",
            "--resource-group",
            "--image-version-id",
            "--uefi-request",
            "--uefi-response",
            "--android-smoke-provenance-sha256",
            "--android-smoke-runtime-sha256",
            "--android-smoke-bundle-sha256",
            "--android-smoke-config-sha256",
            "--contracts",
            "--run-id",
            "--run-attempt",
            "--output",
        });
        defer options.deinit();
        return commands.azureResult(allocator, io, .{
            .manifest = try options.require("--manifest"),
            .asset = try options.require("--asset"),
            .vhd = try options.require("--vhd"),
            .vhd_info = try options.require("--vhd-info"),
            .conversion_attestation = try options.require("--conversion-attestation"),
            .key = try options.require("--key"),
            .source_commit = try options.require("--source-commit"),
            .location = try options.require("--location"),
            .vm_size = try options.require("--vm-size"),
            .resource_group = try options.require("--resource-group"),
            .image_version_id = try options.require("--image-version-id"),
            .uefi_request = try options.require("--uefi-request"),
            .uefi_response = try options.require("--uefi-response"),
            .android_smoke_provenance_sha256 = options.get(
                "--android-smoke-provenance-sha256",
            ),
            .android_smoke_runtime_sha256 = options.get(
                "--android-smoke-runtime-sha256",
            ),
            .android_smoke_bundle_sha256 = options.get(
                "--android-smoke-bundle-sha256",
            ),
            .android_smoke_config_sha256 = options.get(
                "--android-smoke-config-sha256",
            ),
            .contracts = try options.require("--contracts"),
            .run_id = try options.require("--run-id"),
            .run_attempt = try options.require("--run-attempt"),
            .output = try options.require("--output"),
        }, diagnostic);
    }

    if (std.mem.eql(u8, command, "verify-azure-result")) {
        var options = try cli.parse(allocator, argv, &.{
            "--manifest",
            "--asset",
            "--result",
            "--key",
            "--source-commit",
        });
        defer options.deinit();
        var verified = try documents.verifyCandidate(
            allocator,
            io,
            try options.require("--manifest"),
            try options.require("--asset"),
            try options.require("--key"),
            try options.require("--source-commit"),
            diagnostic,
        );
        defer verified.deinit();
        var result = try documents.validateAzureResult(
            allocator,
            io,
            &verified,
            try options.require("--result"),
            diagnostic,
        );
        defer result.deinit();
        try context.out.print("{s}\n{s}\n", .{
            support.stringOf(result.get("qcow_sha256")).?,
            support.stringOf(result.get("flavor")).?,
        });
        try writeJoined(context.out, support.arrayOf(result.get("contracts")).?);
        return;
    }

    if (std.mem.eql(u8, command, "stage")) {
        var options = try cli.parse(allocator, argv, &.{
            "--candidates",
            "--azure-results",
            "--source-commit",
            "--release-tag",
            "--output",
            "--notes",
        });
        defer options.deinit();
        return commands.stage(allocator, io, .{
            .candidates = try options.require("--candidates"),
            .azure_results = try options.require("--azure-results"),
            .source_commit = try options.require("--source-commit"),
            .release_tag = try options.require("--release-tag"),
            .output = try options.require("--output"),
            .notes = try options.require("--notes"),
        }, diagnostic);
    }

    return workflow.dispatch(context.allocator, context.io, context.out, .{
        .command = command,
        .argv = argv,
        .diagnostic = diagnostic,
    });
}

fn writeJoined(out: *std.Io.Writer, items: []const std.json.Value) !void {
    for (items, 0..) |item, index| {
        if (index != 0) try out.writeAll(",");
        try out.writeAll(item.string);
    }
    try out.writeAll("\n");
}

test {
    _ = @import("ubuntu2604/android.zig");
    _ = @import("ubuntu2604/archive.zig");
    _ = @import("ubuntu2604/cli.zig");
    _ = @import("ubuntu2604/commands.zig");
    _ = @import("ubuntu2604/contracts.zig");
    _ = @import("ubuntu2604/documents.zig");
    _ = @import("ubuntu2604/download.zig");
    _ = @import("ubuntu2604/keys.zig");
    _ = @import("ubuntu2604/provenance.zig");
    _ = @import("ubuntu2604/support.zig");
    _ = @import("ubuntu2604/url.zig");
    _ = @import("ubuntu2604/workflow.zig");
}
