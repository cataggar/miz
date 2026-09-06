//! Cross-family source contracts for the canonical Azure Trusted Launch flow.

const std = @import("std");
const trusted_launch = @import("release").azure_trusted_launch;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

const max_file_bytes = 4 * 1024 * 1024;
const max_output_bytes = 1024 * 1024;

fn repositoryRootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_AZURE_TRUSTED_LAUNCH_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn readTracked(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_file_bytes),
    );
}

fn section(text: []const u8, start: []const u8, end: []const u8) ![]const u8 {
    const start_index = std.mem.indexOf(u8, text, start) orelse
        return error.MissingSection;
    const rest = text[start_index + start.len ..];
    const end_index = std.mem.indexOf(u8, rest, end) orelse
        return error.MissingSection;
    return rest[0..end_index];
}

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("missing required text:\n{s}\n", .{needle});
    return error.RequiredTextMissing;
}

fn expectAbsent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("forbidden text is present:\n{s}\n", .{needle});
    return error.ForbiddenTextPresent;
}

fn renderExamples(allocator: Allocator) ![]u8 {
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", "scripts/azure_trusted_launch_examples.sh" },
        .cwd = .{ .path = root },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            allocator.free(result.stdout);
            return error.RendererFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.RendererFailed;
        },
    }
    return result.stdout;
}

test "the canonical command block is generated from production builders" {
    const allocator = std.testing.allocator;
    const document = try readTracked(allocator, "doc/azure-trusted-launch.md");
    defer allocator.free(document);
    const rendered = try renderExamples(allocator);
    defer allocator.free(rendered);

    const actual = try section(
        document,
        "<!-- BEGIN GENERATED AZURE TRUSTED LAUNCH COMMANDS -->\n",
        "<!-- END GENERATED AZURE TRUSTED LAUNCH COMMANDS -->",
    );
    const expected = try std.fmt.allocPrint(
        allocator,
        "```console\n{s}```\n",
        .{rendered},
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, actual);

    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const examples_path = try std.fs.path.join(
        allocator,
        &.{ root, "scripts/azure_trusted_launch_examples.sh" },
    );
    defer allocator.free(examples_path);
    const stat = try Dir.cwd().statFile(std.testing.io, examples_path, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
}

test "documented support equals both protected Azure acceptance matrices" {
    const allocator = std.testing.allocator;
    const document = try readTracked(allocator, "doc/azure-trusted-launch.md");
    defer allocator.free(document);
    const documented = try section(
        document,
        "<!-- BEGIN TRUSTED LAUNCH COVERAGE -->\n",
        "<!-- END TRUSTED LAUNCH COVERAGE -->",
    );
    try std.testing.expectEqual(@as(usize, 8), trusted_launch.acceptance_coverage.len);

    const azurelinux = try readTracked(
        allocator,
        ".github/workflows/azurelinux4-release.yml",
    );
    defer allocator.free(azurelinux);
    const ubuntu = try readTracked(
        allocator,
        ".github/workflows/ubuntu2604-release.yml",
    );
    defer allocator.free(ubuntu);
    const azurelinux_job = try section(azurelinux, "\n  azure_acceptance:", "\n  publish:");
    const ubuntu_job = try section(ubuntu, "\n  azure_acceptance:", "\n  publish:");

    for (trusted_launch.acceptance_coverage) |entry| {
        const row = try std.fmt.allocPrint(
            allocator,
            "| {s} | `{s}` | `{s}` | `{s}` |",
            .{ entry.family, entry.architecture, entry.flavor, entry.asset_name },
        );
        defer allocator.free(row);
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, documented, row));

        const matrix_row = try std.fmt.allocPrint(
            allocator,
            \\          - key: {s}-{s}
            \\            architecture: {s}
            \\            flavor: {s}
            \\            asset_name: {s}
        ,
            .{
                entry.architecture,
                entry.flavor,
                entry.architecture,
                entry.flavor,
                entry.asset_name,
            },
        );
        defer allocator.free(matrix_row);
        const job = if (std.mem.eql(u8, entry.family, "Azure Linux 4"))
            azurelinux_job
        else
            ubuntu_job;
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, job, matrix_row));
    }

    try std.testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, azurelinux_job, "\n          - key: "),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, ubuntu_job, "\n          - key: "),
    );
    for ([_][]const u8{ "baremetal", "bare-metal" }) |excluded| {
        try expectAbsent(documented, excluded);
        try expectAbsent(ubuntu_job, excluded);
    }
}

test "both release families consume every shared resource contract" {
    const allocator = std.testing.allocator;
    const library = try readTracked(allocator, "scripts/azure_trusted_launch_lib.sh");
    defer allocator.free(library);
    const examples = try readTracked(
        allocator,
        "scripts/azure_trusted_launch_examples.sh",
    );
    defer allocator.free(examples);
    const azurelinux = try readTracked(
        allocator,
        "scripts/azurelinux4_azure_acceptance.sh",
    );
    defer allocator.free(azurelinux);
    const ubuntu = try readTracked(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer allocator.free(ubuntu);

    const builders = [_][]const u8{
        "azure_trusted_launch_disk_create_args",
        "azure_trusted_launch_disk_show_args",
        "azure_trusted_launch_disk_revoke_access_args",
        "azure_trusted_launch_gallery_create_args",
        "azure_trusted_launch_image_definition_create_args",
        "azure_trusted_launch_image_definition_show_args",
        "azure_trusted_launch_gallery_version_put_args",
        "azure_trusted_launch_gallery_version_get_args",
        "azure_trusted_launch_vm_create_args",
        "azure_trusted_launch_vm_resource_security_args",
        "azure_trusted_launch_vm_instance_security_args",
    };
    for (builders) |builder| {
        const declaration = try std.fmt.allocPrint(allocator, "{s}() {{", .{builder});
        defer allocator.free(declaration);
        try expectContains(library, declaration);
        try expectContains(examples, builder);
        try expectContains(azurelinux, builder);
        try expectContains(ubuntu, builder);
    }
    for ([_][]const u8{
        "--os-type " ++ trusted_launch.os_type,
        "--os-state " ++ trusted_launch.os_state,
        "--hyper-v-generation " ++ trusted_launch.hyper_v_generation,
        "--features SecurityType=" ++ trusted_launch.image_security_type,
        "api-version=" ++ trusted_launch.gallery_version_api,
        "--security-type " ++ trusted_launch.vm_security_type,
        "--enable-secure-boot true",
        "--enable-vtpm true",
    }) |property| try expectContains(library, property);
    for ([_][]const u8{
        "check-managed-disk",
        "check-image-definition",
        "check-gallery-accepted",
        "check-gallery-final",
        "check-vm-security",
    }) |command| try expectContains(azurelinux, command);
    for ([_][]const u8{
        "azure-managed-disk",
        "azure-image-definition",
        "azure-gallery-accepted",
        "azure-gallery-verify",
        "azure-vm-security",
    }) |command| try expectContains(ubuntu, command);
    try expectContains(ubuntu, "api-version=" ++ trusted_launch.vm_api);
    try expectContains(
        ubuntu,
        "securityType: \"" ++ trusted_launch.vm_security_type ++ "\"",
    );
}

test "all operator documentation links to the canonical guide" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "doc/readme.md",
        "doc/getting-started.md",
        "doc/azure-linux.md",
        "doc/ubuntu.md",
    }) |path| {
        const document = try readTracked(allocator, path);
        defer allocator.free(document);
        try expectContains(document, "azure-trusted-launch.md");
    }
}
