//! Command-line surfaces for the FreeBSD 15.1 release tooling.
//!
//! The subcommand and option tables are data rather than parsing code so the
//! contract tests can compare them directly with the release workflow and the
//! acceptance harness: an invocation that names an option the parser does not
//! accept, or omits one it requires, is a defect the tests catch statically
//! instead of a release job discovering it at three in the morning.

const std = @import("std");
const profiles = @import("profiles.zig");
const document = @import("document.zig");
const candidate_support = @import("candidate.zig");
const staging = @import("staging.zig");
const publication = @import("publication.zig");
const azure_metadata = @import("azure_metadata.zig");
const support = @import("release");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const Writer = std.Io.Writer;
const Context = document.Context;
const json_document = support.json_document;

/// `argparse`'s exit code for a usage error, kept so the shell callers cannot
/// confuse "the command was spelled wrong" with "the release is invalid".
pub const usage_exit_code = 2;
pub const failure_exit_code = 1;

pub const Command = struct {
    name: []const u8,
    /// Long option names, without the leading `--`, in the order the parser
    /// declares them.
    options: []const []const u8,
    required: []const []const u8,
};

/// Every `freebsd15_release` subcommand and the options it accepts.
pub const release_commands = [_]Command{
    .{
        .name = "matrix",
        .options = &.{"release-set"},
        .required = &.{"release-set"},
    },
    .{
        .name = "azure-matrix",
        .options = &.{"release-set"},
        .required = &.{"release-set"},
    },
    .{
        .name = "describe",
        .options = &.{ "release-set", "release-date" },
        .required = &.{"release-set"},
    },
    .{
        .name = "include-count",
        .options = &.{"matrix"},
        .required = &.{"matrix"},
    },
    .{
        .name = "candidate",
        .options = &.{
            "architecture",
            "filesystem",
            "flavor",
            "package-manifest",
            "asset",
            "validated-sha256",
            "virtual-size",
            "qemu-info",
            "source-name",
            "source-url",
            "source-sha256",
            "source-bytes",
            "source-commit",
            "qemu-version",
            "runner",
            "run-id",
            "run-attempt",
            "output",
        },
        .required = &.{
            "architecture",
            "filesystem",
            "flavor",
            "package-manifest",
            "asset",
            "validated-sha256",
            "virtual-size",
            "qemu-info",
            "source-name",
            "source-url",
            "source-sha256",
            "source-bytes",
            "source-commit",
            "qemu-version",
            "runner",
            "run-id",
            "run-attempt",
            "output",
        },
    },
    .{
        .name = "azure-result",
        .options = &.{
            "manifest",
            "asset",
            "key",
            "source-commit",
            "vhd-sha256",
            "vhd-bytes",
            "vhd-current-size",
            "contracts",
            "location",
            "vm-size",
            "resource-group",
            "run-id",
            "run-attempt",
            "output",
        },
        .required = &.{
            "manifest",
            "asset",
            "key",
            "source-commit",
            "vhd-sha256",
            "vhd-bytes",
            "vhd-current-size",
            "contracts",
            "location",
            "vm-size",
            "resource-group",
            "run-id",
            "run-attempt",
            "output",
        },
    },
    .{
        .name = "candidate-binding",
        .options = &.{
            "manifest",
            "asset",
            "key",
            "source-commit",
            "architecture",
            "filesystem",
            "flavor",
            "asset-name",
            "run-id",
            "run-attempt",
        },
        .required = &.{
            "manifest",
            "asset",
            "key",
            "source-commit",
            "architecture",
            "filesystem",
            "flavor",
            "asset-name",
            "run-id",
            "run-attempt",
        },
    },
    .{
        .name = "stage",
        .options = &.{
            "release-set",
            "candidates",
            "source-commit",
            "release-tag",
            "release-date",
            "azure-results",
            "minimum-core-reduction-percent",
            "output",
            "notes",
        },
        .required = &.{
            "release-set",
            "candidates",
            "source-commit",
            "release-tag",
            "output",
            "notes",
        },
    },
    .{
        .name = "compare",
        .options = &.{ "candidate", "output" },
        .required = &.{"candidate"},
    },
    .{
        .name = "stage-expected",
        .options = &.{ "manifest", "release-set" },
        .required = &.{ "manifest", "release-set" },
    },
    .{
        .name = "stage-evidence",
        .options = &.{ "release-set", "manifest", "azure-results", "evidence" },
        .required = &.{ "release-set", "manifest", "azure-results", "evidence" },
    },
    .{
        .name = "publish-expected",
        .options = &.{
            "manifest",
            "assets",
            "release-set",
            "release-tag",
            "source-commit",
            "asset-count",
        },
        .required = &.{
            "manifest",
            "assets",
            "release-set",
            "release-tag",
            "source-commit",
            "asset-count",
        },
    },
    .{
        .name = "tag-object",
        .options = &.{ "refs", "tag" },
        .required = &.{ "refs", "tag" },
    },
    .{
        .name = "verify-remote-release",
        .options = &.{ "release", "expected" },
        .required = &.{ "release", "expected" },
    },
    .{
        .name = "verify-downloaded-release",
        .options = &.{ "directory", "expected" },
        .required = &.{ "directory", "expected" },
    },
    .{
        .name = "verify-published-release",
        .options = &.{ "release", "expected" },
        .required = &.{ "release", "expected" },
    },
};

pub fn findCommand(name: []const u8) ?*const Command {
    for (&release_commands) |*command| {
        if (std.mem.eql(u8, command.name, name)) return command;
    }
    return null;
}

/// Every `freebsd15_azure_metadata` subcommand and how many positional
/// arguments it takes, matching the Python `COMMANDS` table.
pub const MetadataCommand = struct {
    name: []const u8,
    arguments: usize,
};

pub const metadata_commands = [_]MetadataCommand{
    .{ .name = "managed-disk", .arguments = 7 },
    .{ .name = "gallery", .arguments = 5 },
    .{ .name = "gallery-image-definition", .arguments = 9 },
    .{ .name = "gallery-image-version", .arguments = 8 },
    .{ .name = "vm", .arguments = 10 },
    .{ .name = "group-tags", .arguments = 4 },
    .{ .name = "disk-access-sas", .arguments = 1 },
    .{ .name = "location-display-name", .arguments = 2 },
    .{ .name = "vm-sku", .arguments = 3 },
    .{ .name = "boot-diagnostics", .arguments = 1 },
    .{ .name = "replication-status", .arguments = 3 },
    .{ .name = "serial-console", .arguments = 2 },
};

pub fn findMetadataCommand(name: []const u8) ?*const MetadataCommand {
    for (&metadata_commands) |*command| {
        if (std.mem.eql(u8, command.name, name)) return command;
    }
    return null;
}

// ---- Option parsing -------------------------------------------------------

const Option = struct {
    name: []const u8,
    value: []const u8,
};

const Options = struct {
    entries: []const Option,

    fn find(self: Options, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
        return null;
    }
};

const ParseError = error{ Usage, OutOfMemory };

fn parseOptions(
    allocator: Allocator,
    command: *const Command,
    argv: []const []const u8,
) ParseError!Options {
    var entries: std.ArrayList(Option) = .empty;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (!std.mem.startsWith(u8, argument, "--")) return error.Usage;
        const body = argument[2..];
        const split = std.mem.indexOfScalar(u8, body, '=');
        const name = if (split) |at| body[0..at] else body;
        if (!isAccepted(command, name)) return error.Usage;
        const value = if (split) |at| body[at + 1 ..] else blk: {
            index += 1;
            if (index >= argv.len) return error.Usage;
            break :blk argv[index];
        };
        for (entries.items) |existing| {
            if (std.mem.eql(u8, existing.name, name)) return error.Usage;
        }
        try entries.append(allocator, .{ .name = name, .value = value });
    }
    for (command.required) |name| {
        var found = false;
        for (entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) found = true;
        }
        if (!found) return error.Usage;
    }
    return .{ .entries = entries.items };
}

fn isAccepted(command: *const Command, name: []const u8) bool {
    for (command.options) |option| {
        if (std.mem.eql(u8, option, name)) return true;
    }
    return false;
}

fn requiredOption(options: Options, name: []const u8) []const u8 {
    return options.find(name).?;
}

fn integerOption(options: Options, name: []const u8, fallback: i64) ParseError!i64 {
    const text = options.find(name) orelse return fallback;
    return std.fmt.parseInt(i64, text, 10) catch error.Usage;
}

const release_usage_text =
    \\usage: freebsd15_release COMMAND [OPTIONS]
    \\
    \\Validate, stage, and publish FreeBSD 15.1 release artifacts.
    \\
    \\commands:
    \\  matrix, azure-matrix, describe, include-count, candidate, azure-result,
    \\  candidate-binding, stage, compare, stage-expected, stage-evidence,
    \\  publish-expected, tag-object, verify-remote-release,
    \\  verify-downloaded-release, verify-published-release
    \\
;

// ---- freebsd15_release ----------------------------------------------------

pub fn runRelease(init: std.process.Init) !void {
    const io = init.io;
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    var context: Context = .{ .gpa = init.gpa, .arena = arena, .io = io };
    dispatchRelease(&context, argv, out) catch |err| switch (err) {
        error.Usage => {
            try err_out.writeAll(release_usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        },
        error.Invalid => {
            try err_out.print("{s}\n", .{context.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        },
        else => return err,
    };
    try out.flush();
}

fn dispatchRelease(
    context: *Context,
    argv: []const []const u8,
    out: *Writer,
) (document.Error || ParseError)!void {
    if (argv.len < 2) return error.Usage;
    const command = findCommand(argv[1]) orelse return error.Usage;
    const options = try parseOptions(context.arena, command, argv[2..]);
    const name = command.name;

    if (std.mem.eql(u8, name, "matrix")) {
        return matrixCommand(context, requiredOption(options, "release-set"), out);
    }
    if (std.mem.eql(u8, name, "azure-matrix")) {
        return azureMatrixCommand(context, requiredOption(options, "release-set"), out);
    }
    if (std.mem.eql(u8, name, "describe")) {
        return describeCommand(
            context,
            requiredOption(options, "release-set"),
            options.find("release-date"),
            out,
        );
    }
    if (std.mem.eql(u8, name, "include-count")) {
        return includeCountCommand(context, requiredOption(options, "matrix"), out);
    }
    if (std.mem.eql(u8, name, "candidate")) {
        return candidate_support.candidateCommand(context, .{
            .architecture = requiredOption(options, "architecture"),
            .filesystem = requiredOption(options, "filesystem"),
            .flavor = requiredOption(options, "flavor"),
            .package_manifest = requiredOption(options, "package-manifest"),
            .asset = requiredOption(options, "asset"),
            .validated_sha256 = requiredOption(options, "validated-sha256"),
            .virtual_size = try integerOption(options, "virtual-size", 0),
            .qemu_info = requiredOption(options, "qemu-info"),
            .source_name = requiredOption(options, "source-name"),
            .source_url = requiredOption(options, "source-url"),
            .source_sha256 = requiredOption(options, "source-sha256"),
            .source_bytes = try integerOption(options, "source-bytes", 0),
            .source_commit = requiredOption(options, "source-commit"),
            .qemu_version = requiredOption(options, "qemu-version"),
            .runner = requiredOption(options, "runner"),
            .run_id = requiredOption(options, "run-id"),
            .run_attempt = requiredOption(options, "run-attempt"),
            .output = requiredOption(options, "output"),
        });
    }
    if (std.mem.eql(u8, name, "azure-result")) {
        return candidate_support.azureResultCommand(context, .{
            .manifest = requiredOption(options, "manifest"),
            .asset = requiredOption(options, "asset"),
            .key = requiredOption(options, "key"),
            .source_commit = requiredOption(options, "source-commit"),
            .vhd_sha256 = requiredOption(options, "vhd-sha256"),
            .vhd_bytes = try integerOption(options, "vhd-bytes", 0),
            .vhd_current_size = try integerOption(options, "vhd-current-size", 0),
            .contracts = requiredOption(options, "contracts"),
            .location = requiredOption(options, "location"),
            .vm_size = requiredOption(options, "vm-size"),
            .resource_group = requiredOption(options, "resource-group"),
            .run_id = requiredOption(options, "run-id"),
            .run_attempt = requiredOption(options, "run-attempt"),
            .output = requiredOption(options, "output"),
        });
    }
    if (std.mem.eql(u8, name, "candidate-binding")) {
        return candidate_support.candidateBinding(context, .{
            .manifest = requiredOption(options, "manifest"),
            .asset = requiredOption(options, "asset"),
            .key = requiredOption(options, "key"),
            .source_commit = requiredOption(options, "source-commit"),
            .architecture = requiredOption(options, "architecture"),
            .filesystem = requiredOption(options, "filesystem"),
            .flavor = requiredOption(options, "flavor"),
            .asset_name = requiredOption(options, "asset-name"),
            .run_id = requiredOption(options, "run-id"),
            .run_attempt = requiredOption(options, "run-attempt"),
        }, out);
    }
    if (std.mem.eql(u8, name, "stage")) {
        return staging.stageCommand(context, .{
            .release_set = requiredOption(options, "release-set"),
            .candidates = requiredOption(options, "candidates"),
            .source_commit = requiredOption(options, "source-commit"),
            .release_tag = requiredOption(options, "release-tag"),
            .release_date = options.find("release-date"),
            .azure_results = options.find("azure-results"),
            .minimum_core_reduction_percent = try integerOption(
                options,
                "minimum-core-reduction-percent",
                profiles.core_minimum_reduction_percent,
            ),
            .output = requiredOption(options, "output"),
            .notes = requiredOption(options, "notes"),
        });
    }
    if (std.mem.eql(u8, name, "compare")) {
        const report = try staging.compareReport(
            context,
            requiredOption(options, "candidate"),
        );
        if (options.find("output")) |path| {
            try candidate_support.writeText(context, path, report);
        }
        out.writeAll(report) catch return error.OutOfMemory;
        return;
    }
    if (std.mem.eql(u8, name, "stage-expected")) {
        return publication.stagedExpected(
            context,
            requiredOption(options, "manifest"),
            requiredOption(options, "release-set"),
            out,
        );
    }
    if (std.mem.eql(u8, name, "stage-evidence")) {
        return publication.stageEvidence(
            context,
            requiredOption(options, "release-set"),
            requiredOption(options, "manifest"),
            requiredOption(options, "azure-results"),
            requiredOption(options, "evidence"),
        );
    }
    if (std.mem.eql(u8, name, "publish-expected")) {
        return publication.publishExpected(context, .{
            .manifest = requiredOption(options, "manifest"),
            .assets = requiredOption(options, "assets"),
            .release_set = requiredOption(options, "release-set"),
            .release_tag = requiredOption(options, "release-tag"),
            .source_commit = requiredOption(options, "source-commit"),
            .asset_count = try integerOption(options, "asset-count", 0),
        }, out);
    }
    if (std.mem.eql(u8, name, "tag-object")) {
        return publication.tagObject(
            context,
            requiredOption(options, "refs"),
            requiredOption(options, "tag"),
            out,
        );
    }
    if (std.mem.eql(u8, name, "verify-remote-release")) {
        return publication.verifyRemoteRelease(
            context,
            requiredOption(options, "release"),
            requiredOption(options, "expected"),
        );
    }
    if (std.mem.eql(u8, name, "verify-downloaded-release")) {
        return publication.verifyDownloadedRelease(
            context,
            requiredOption(options, "directory"),
            requiredOption(options, "expected"),
        );
    }
    if (std.mem.eql(u8, name, "verify-published-release")) {
        return publication.verifyPublishedRelease(
            context,
            requiredOption(options, "release"),
            requiredOption(options, "expected"),
        );
    }
    return error.Usage;
}

/// `matrix_command`: the build matrix for one release set. The document is
/// consumed only by `fromJSON`, so it is emitted in the canonical compact
/// spelling rather than the Python default separators.
pub fn matrixCommand(
    context: *Context,
    release_set: []const u8,
    out: *Writer,
) document.Error!void {
    const selected = try candidate_support.requireReleaseSet(context, release_set);
    var include: std.json.Array = .init(context.arena);
    for (selected.variants) |key| {
        const variant = profiles.findVariant(key).?;
        var url_buffer: [profiles.max_source_url_len]u8 = undefined;
        var entry: std.json.ObjectMap = .empty;
        try entry.put(context.arena, "variant", .{ .string = variant.key });
        try entry.put(context.arena, "architecture", .{ .string = variant.architecture });
        try entry.put(context.arena, "filesystem", .{ .string = variant.filesystem });
        try entry.put(context.arena, "flavor", .{ .string = variant.flavor });
        try entry.put(context.arena, "asset_name", .{ .string = variant.asset_name });
        try entry.put(context.arena, "source_name", .{ .string = variant.source_name });
        try entry.put(context.arena, "source_url", .{
            .string = try context.arena.dupe(u8, variant.sourceUrl(&url_buffer)),
        });
        try entry.put(context.arena, "source_sha256", .{ .string = variant.source_sha256 });
        try entry.put(context.arena, "virtual_size", .{ .integer = @intCast(variant.virtual_size) });
        try entry.put(context.arena, "runner", .{ .string = variant.runner });
        try entry.put(context.arena, "qemu", .{ .string = variant.qemu });
        try entry.put(context.arena, "release_role", .{ .string = "release" });
        try include.append(.{ .object = entry });
    }
    try writeInclude(context, include, out);
}

/// `azure_matrix_command`.
pub fn azureMatrixCommand(
    context: *Context,
    release_set: []const u8,
    out: *Writer,
) document.Error!void {
    const selected = try candidate_support.requireReleaseSet(context, release_set);
    var include: std.json.Array = .init(context.arena);
    for (selected.variants) |key| {
        const variant = profiles.findVariant(key).?;
        const arm64 = std.mem.eql(u8, variant.architecture, "aarch64");
        var entry: std.json.ObjectMap = .empty;
        try entry.put(context.arena, "key", .{ .string = variant.key });
        try entry.put(context.arena, "architecture", .{ .string = variant.architecture });
        try entry.put(context.arena, "filesystem", .{ .string = variant.filesystem });
        try entry.put(context.arena, "flavor", .{ .string = variant.flavor });
        try entry.put(context.arena, "asset_name", .{ .string = variant.asset_name });
        try entry.put(context.arena, "location_variable", .{
            .string = if (arm64) "AZURE_LOCATION_ARM64" else "AZURE_LOCATION_X64",
        });
        try entry.put(context.arena, "size_variable", .{
            .string = if (arm64) "AZURE_VM_SIZE_ARM64" else "AZURE_VM_SIZE_X64",
        });
        try include.append(.{ .object = entry });
    }
    try writeInclude(context, include, out);
}

fn writeInclude(
    context: *Context,
    include: std.json.Array,
    out: *Writer,
) document.Error!void {
    var root: std.json.ObjectMap = .empty;
    try root.put(context.arena, "include", .{ .array = include });
    const bytes = json_document.canonicalAlloc(
        context.arena,
        .{ .object = root },
        .compact,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot serialize the release matrix", .{}),
    };
    out.print("{s}\n", .{bytes}) catch return error.OutOfMemory;
}

/// `describe_command`.
pub fn describeCommand(
    context: *Context,
    release_set: []const u8,
    release_date: ?[]const u8,
    out: *Writer,
) document.Error!void {
    const selected = try candidate_support.requireReleaseSet(context, release_set);
    const identity = try candidate_support.releaseIdentity(
        context,
        release_set,
        release_date,
    );
    out.print(
        "release_tag={s}\nrelease_title={s}\nasset_count={d}\n" ++
            "core_minimum_reduction_percent={d}\n",
        .{
            identity.tag,
            identity.title,
            selected.variants.len,
            profiles.core_minimum_reduction_percent,
        },
    ) catch return error.OutOfMemory;
}

/// The `include` length of an emitted matrix, so the workflow can prove the
/// matrix it is about to fan out over is the size it expects.
pub fn includeCountCommand(
    context: *Context,
    matrix: []const u8,
    out: *Writer,
) document.Error!void {
    const parsed = std.json.parseFromSlice(
        Value,
        context.arena,
        matrix,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("release matrix is not valid JSON", .{}),
    };
    const root = document.objectOf(parsed.value) orelse return context.fail(
        "release matrix is not a JSON object",
        .{},
    );
    const include = document.arrayOf(root.get("include")) orelse return context.fail(
        "release matrix has no include list",
        .{},
    );
    out.print("{d}\n", .{include.items.len}) catch return error.OutOfMemory;
}

// ---- freebsd15_azure_metadata ---------------------------------------------

pub fn runAzureMetadata(init: std.process.Init) !void {
    const io = init.io;
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    const program = if (argv.len > 0) argv[0] else "freebsd15_azure_metadata";
    if (argv.len < 2 or findMetadataCommand(argv[1]) == null) {
        try err_out.print("usage: {s} {{", .{program});
        for (metadata_commands, 0..) |command, index| {
            if (index > 0) try err_out.writeAll(",");
            try err_out.writeAll(command.name);
        }
        try err_out.writeAll("} VALIDATION_ARGUMENTS...\n");
        try err_out.flush();
        std.process.exit(failure_exit_code);
    }
    const command = findMetadataCommand(argv[1]).?;
    const arguments = argv[2..];
    if (arguments.len != command.arguments) {
        try err_out.print("{s} expects {d} arguments, got {d}\n", .{
            command.name,
            command.arguments,
            arguments.len,
        });
        try err_out.flush();
        std.process.exit(failure_exit_code);
    }

    var context: Context = .{ .gpa = init.gpa, .arena = arena, .io = io };
    const exit_code = dispatchMetadata(&context, command.name, arguments, out) catch |err|
        switch (err) {
            error.Invalid => {
                try err_out.print("{s}\n", .{context.message()});
                try err_out.flush();
                std.process.exit(failure_exit_code);
            },
            else => return err,
        };
    try out.flush();
    if (exit_code != 0) std.process.exit(exit_code);
}

fn dispatchMetadata(
    context: *Context,
    name: []const u8,
    arguments: []const []const u8,
    out: *Writer,
) document.Error!u8 {
    if (std.mem.eql(u8, name, "managed-disk")) {
        try azure_metadata.validateManagedDisk(context, .{
            .path = arguments[0],
            .expected_id = arguments[1],
            .expected_name = arguments[2],
            .expected_group = arguments[3],
            .expected_location = arguments[4],
            .expected_architecture = arguments[5],
            .expected_size_gib = arguments[6],
        }, out);
        return 0;
    }
    if (std.mem.eql(u8, name, "gallery")) {
        try azure_metadata.validateGallery(context, .{
            .path = arguments[0],
            .expected_id = arguments[1],
            .expected_name = arguments[2],
            .expected_group = arguments[3],
            .expected_location = arguments[4],
        });
        return 0;
    }
    if (std.mem.eql(u8, name, "gallery-image-definition")) {
        try azure_metadata.validateGalleryImageDefinition(context, .{
            .path = arguments[0],
            .expected_id = arguments[1],
            .expected_name = arguments[2],
            .expected_group = arguments[3],
            .expected_location = arguments[4],
            .expected_architecture = arguments[5],
            .expected_publisher = arguments[6],
            .expected_offer = arguments[7],
            .expected_sku = arguments[8],
        });
        return 0;
    }
    if (std.mem.eql(u8, name, "gallery-image-version")) {
        try azure_metadata.validateGalleryImageVersion(context, .{
            .path = arguments[0],
            .expected_id = arguments[1],
            .expected_name = arguments[2],
            .expected_group = arguments[3],
            .expected_location = arguments[4],
            .expected_location_display_name = arguments[5],
            .expected_disk_id = arguments[6],
            .expected_size_gib = arguments[7],
        });
        return 0;
    }
    if (std.mem.eql(u8, name, "vm")) {
        try azure_metadata.validateVm(context, .{
            .path = arguments[0],
            .expected_id = arguments[1],
            .expected_name = arguments[2],
            .expected_group = arguments[3],
            .expected_location = arguments[4],
            .expected_size = arguments[5],
            .expected_image_version_id = arguments[6],
            .expected_admin = arguments[7],
            .expected_architecture = arguments[8],
            .expected_size_gib = arguments[9],
        }, out);
        return 0;
    }
    if (std.mem.eql(u8, name, "group-tags")) {
        try azure_metadata.validateGroupTags(
            context,
            arguments[0],
            arguments[1],
            arguments[2],
            arguments[3],
        );
        return 0;
    }
    if (std.mem.eql(u8, name, "disk-access-sas")) {
        try azure_metadata.diskAccessSas(context, arguments[0], out);
        return 0;
    }
    if (std.mem.eql(u8, name, "location-display-name")) {
        try azure_metadata.locationDisplayName(
            context,
            arguments[0],
            arguments[1],
            out,
        );
        return 0;
    }
    if (std.mem.eql(u8, name, "vm-sku")) {
        try azure_metadata.validateVmSku(
            context,
            arguments[0],
            arguments[1],
            arguments[2],
        );
        return 0;
    }
    if (std.mem.eql(u8, name, "boot-diagnostics")) {
        try azure_metadata.bootDiagnosticsObservation(context, arguments[0], out);
        return 0;
    }
    if (std.mem.eql(u8, name, "replication-status")) {
        try azure_metadata.replicationObservation(
            context,
            arguments[0],
            arguments[1],
            arguments[2],
            out,
        );
        return 0;
    }
    if (std.mem.eql(u8, name, "serial-console")) {
        const result = try azure_metadata.normalizeSerialConsole(
            context,
            arguments[0],
            arguments[1],
        );
        return @intFromEnum(result);
    }
    unreachable;
}

test "every declared release command requires only options it accepts" {
    var previous_names: [release_commands.len][]const u8 = undefined;
    for (release_commands, 0..) |command, index| {
        try std.testing.expect(command.name.len > 0);
        for (0..index) |seen| {
            try std.testing.expect(
                !std.mem.eql(u8, previous_names[seen], command.name),
            );
        }
        previous_names[index] = command.name;
        for (command.required) |name| {
            try std.testing.expect(isAccepted(&command, name));
        }
        for (command.options, 0..) |option, position| {
            for (0..position) |earlier| {
                try std.testing.expect(
                    !std.mem.eql(u8, command.options[earlier], option),
                );
            }
        }
    }
}

test "option parsing accepts both spellings and refuses the rest" {
    const command = findCommand("compare").?;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const spaced = try parseOptions(arena.allocator(), command, &.{
        "--candidate", "manifest.json",
        "--output",    "report.md",
    });
    try std.testing.expectEqualStrings("manifest.json", spaced.find("candidate").?);
    try std.testing.expectEqualStrings("report.md", spaced.find("output").?);

    const joined = try parseOptions(arena.allocator(), command, &.{
        "--candidate=manifest.json",
    });
    try std.testing.expectEqualStrings("manifest.json", joined.find("candidate").?);
    try std.testing.expectEqual(@as(?[]const u8, null), joined.find("output"));

    try std.testing.expectError(
        error.Usage,
        parseOptions(arena.allocator(), command, &.{"--output=report.md"}),
    );
    try std.testing.expectError(
        error.Usage,
        parseOptions(arena.allocator(), command, &.{ "--candidate", "a", "--extra", "b" }),
    );
    try std.testing.expectError(
        error.Usage,
        parseOptions(arena.allocator(), command, &.{ "--candidate", "a", "--candidate", "b" }),
    );
    try std.testing.expectError(
        error.Usage,
        parseOptions(arena.allocator(), command, &.{"--candidate"}),
    );
    try std.testing.expectError(
        error.Usage,
        parseOptions(arena.allocator(), command, &.{"candidate"}),
    );
}

test "metadata commands keep the Python argument counts" {
    try std.testing.expectEqual(@as(usize, 7), findMetadataCommand("managed-disk").?.arguments);
    try std.testing.expectEqual(@as(usize, 5), findMetadataCommand("gallery").?.arguments);
    try std.testing.expectEqual(
        @as(usize, 8),
        findMetadataCommand("gallery-image-version").?.arguments,
    );
    try std.testing.expectEqual(@as(usize, 10), findMetadataCommand("vm").?.arguments);
    try std.testing.expectEqual(
        @as(?*const MetadataCommand, null),
        findMetadataCommand("disk"),
    );
}
