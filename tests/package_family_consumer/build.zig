const std = @import("std");

pub fn build(b: *std.Build) void {
    const default_optimize: std.lang.Optimize = switch (b.graph.release_mode) {
        .off, .any, .safe => .safe,
        .fast => .fast,
        .small => .small,
    };
    const optimize = b.option(
        std.lang.Optimize,
        "optimize",
        "Prioritize performance, safety, or binary size",
    ) orelse default_optimize;
    const dependency = b.dependency("image_toolkit", .{
        .target = b.graph.host,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
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
