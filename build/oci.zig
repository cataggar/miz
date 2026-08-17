const std = @import("std");
const builtin = @import("builtin");
const reference = @import("../packages/vmiz/src/oci/reference.zig");

pub const Platform = struct {
    os: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    variant: ?[]const u8 = null,
};

pub const Options = struct {
    name: []const u8,
    /// Fully qualified immutable registry reference.
    source: []const u8,
    platform: Platform = .{},
    authfile: ?std.Build.LazyPath = null,
    tls_ca: ?std.Build.LazyPath = null,
    plain_http: bool = false,
};

pub const Result = struct {
    layout: std.Build.LazyPath,
    step: *std.Build.Step.Run,
};

pub const SourceValidationError = error{
    InvalidSource,
    MutableSource,
};

pub fn add(
    b: *std.Build,
    dependency: *std.Build.Dependency,
    options: Options,
) Result {
    validateName(options.name);
    validateSource(options.source) catch |err| switch (err) {
        error.InvalidSource => @panic(
            "OCI pull source must be a valid digest-pinned docker:// registry reference",
        ),
        error.MutableSource => @panic(
            "OCI pull source must be digest-pinned, not tagged",
        ),
    };
    const os = options.platform.os orelse hostOs();
    const architecture = options.platform.architecture orelse hostArchitecture();
    validatePlatform(os);
    validatePlatform(architecture);
    if (options.platform.variant) |variant| validatePlatform(variant);

    const run = b.addRunArtifact(dependency.artifact("vmiz"));
    run.setName(b.fmt("pull OCI image {s}", .{options.name}));
    run.addArgs(&.{
        "oci",
        "copy",
        "--override-os",
        os,
        "--override-arch",
        architecture,
    });
    if (options.platform.variant) |variant| {
        run.addArgs(&.{ "--override-variant", variant });
    }
    if (options.authfile) |path| {
        run.addArg("--src-authfile");
        run.addFileArg(path);
    }
    if (options.tls_ca) |path| {
        run.addArg("--src-tls-ca");
        run.addFileArg(path);
    }
    if (options.plain_http) run.addArg("--src-plain-http");
    run.addArg(options.source);
    const layout = run.addPrefixedOutputDirectoryArg(
        "oci:",
        b.fmt("{s}-oci-layout", .{options.name}),
    );
    return .{ .layout = layout, .step = run };
}

pub fn validateSource(source: []const u8) SourceValidationError!void {
    const parsed = reference.parse(source, .source) catch
        return error.InvalidSource;
    const registry = switch (parsed) {
        .registry => |value| value,
        .layout => return error.InvalidSource,
    };
    const selection = registry.selection orelse
        return error.InvalidSource;
    switch (selection) {
        .digest => {},
        .tag => return error.MutableSource,
    }
}

fn validateName(name: []const u8) void {
    if (name.len == 0 or
        std.mem.indexOfScalar(u8, name, 0) != null or
        std.fs.path.isAbsolute(name) or
        !std.mem.eql(u8, name, std.fs.path.basename(name)) or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        @panic("OCI pull name must be a non-empty path component");
    }
}

fn validatePlatform(value: []const u8) void {
    if (value.len == 0 or value.len > 128) {
        @panic("OCI pull platform components must be non-empty and bounded");
    }
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '_' and byte != '.' and byte != '-')
        {
            @panic("OCI pull platform components contain an invalid byte");
        }
    }
}

fn hostOs() []const u8 {
    return switch (builtin.os.tag) {
        .macos => "darwin",
        else => @tagName(builtin.os.tag),
    };
}

fn hostArchitecture() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    };
}

test "OCI pull sources require immutable registry digests" {
    try validateSource(
        "docker://registry.example/team/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    try std.testing.expectError(
        error.MutableSource,
        validateSource("docker://registry.example/team/image:latest"),
    );
    try std.testing.expectError(
        error.InvalidSource,
        validateSource("oci:layout@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    );
}
