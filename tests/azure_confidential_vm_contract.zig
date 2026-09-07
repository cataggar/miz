//! Source contracts for the canonical Azure Confidential VM flow.

const std = @import("std");
const confidential = @import("release").azure_confidential_vm;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

const max_file_bytes = 4 * 1024 * 1024;
const max_output_bytes = 1024 * 1024;

fn repositoryRootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_AZURE_CONFIDENTIAL_VM_ROOT",
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
        .argv = &.{ "bash", "scripts/azure_confidential_vm_examples.sh" },
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

test "canonical commands are generated from Confidential VM builders" {
    const allocator = std.testing.allocator;
    const document = try readTracked(allocator, "doc/azure-confidential-vm.md");
    defer allocator.free(document);
    const rendered = try renderExamples(allocator);
    defer allocator.free(rendered);
    const actual = try section(
        document,
        "<!-- BEGIN GENERATED AZURE CONFIDENTIAL VM COMMANDS -->\n",
        "<!-- END GENERATED AZURE CONFIDENTIAL VM COMMANDS -->",
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
        &.{ root, "scripts/azure_confidential_vm_examples.sh" },
    );
    defer allocator.free(examples_path);
    const stat = try Dir.cwd().statFile(std.testing.io, examples_path, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
}

test "builders encode every independent Confidential VM resource contract" {
    const allocator = std.testing.allocator;
    const library = try readTracked(
        allocator,
        "scripts/azure_confidential_vm_lib.sh",
    );
    defer allocator.free(library);
    const examples = try readTracked(
        allocator,
        "scripts/azure_confidential_vm_examples.sh",
    );
    defer allocator.free(examples);
    const contract_source = try readTracked(
        allocator,
        "scripts/release/azure_confidential_vm.zig",
    );
    defer allocator.free(contract_source);

    const builders = [_][]const u8{
        "azure_confidential_vm_sku_list_args",
        "azure_confidential_vm_image_definition_create_args",
        "azure_confidential_vm_image_definition_show_args",
        "azure_confidential_vm_managed_image_create_args",
        "azure_confidential_vm_managed_image_show_args",
        "azure_confidential_vm_vm_create_args",
        "azure_confidential_vm_vm_resource_args",
        "azure_confidential_vm_vm_instance_security_args",
    };
    for (builders) |builder| {
        const declaration = try std.fmt.allocPrint(
            allocator,
            "{s}() {{",
            .{builder},
        );
        defer allocator.free(declaration);
        try expectContains(library, declaration);
        try expectContains(examples, builder);
    }
    for ([_][]const u8{
        "--architecture " ++ confidential.architecture,
        "--features SecurityType=" ++ confidential.image_security_feature,
        "--security-type " ++ confidential.vm_security_type,
        "--os-disk-security-encryption-type " ++
            confidential.os_disk_security_encryption_type,
        "--enable-secure-boot true",
        "--enable-vtpm true",
        "ConfidentialComputingType",
    }) |property| {
        if (std.mem.eql(u8, property, "ConfidentialComputingType")) {
            try expectContains(contract_source, property);
        } else {
            try expectContains(library, property);
        }
    }
    try expectContains(
        examples,
        "source \"$script_dir/azure_trusted_launch_lib.sh\"",
    );
    try expectAbsent(library, "eval ");
    try expectAbsent(examples, "eval ");
}

test "documentation states the qualified and excluded support boundary" {
    const allocator = std.testing.allocator;
    const document = try readTracked(allocator, "doc/azure-confidential-vm.md");
    defer allocator.free(document);
    for ([_][]const u8{
        "Ubuntu 24.04 LTS",
        "AMD SEV-SNP",
        "`SecurityType=ConfidentialVMSupported`",
        "`securityType=ConfidentialVM`",
        "`securityEncryptionType=VMGuestStateOnly`",
        "strictly smaller than 32 GiB",
        "Arm64 and Intel TDX are not part of this initial contract",
        "does not append the miz release certificate",
    }) |claim| try expectContains(document, claim);

    for ([_][]const u8{
        "doc/readme.md",
        "doc/getting-started.md",
    }) |path| {
        const index = try readTracked(allocator, path);
        defer allocator.free(index);
        try expectContains(index, "azure-confidential-vm.md");
    }
}
