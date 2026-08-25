const std = @import("std");

pub fn build(b: *std.Build) void {
    const dependency = b.dependency("image_toolkit", .{
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{
                    .name = "package_family_host",
                    .module = dependency.module("miz-package-family-host"),
                },
            },
        }),
    });
    const run = b.addRunArtifact(tests);
    b.step("check", "Compile and run the public host adapter consumer")
        .dependOn(&run.step);
}
