const std = @import("std");

pub fn addHeaders(module: *std.Build.Module, dependency: *std.Build.Dependency) void {
    const b = module.owner;
    const Translator = @import("translate_c").Translator;
    // Share the helper modules from the package instance used by debz and rpmz.
    const translator = Translator.init(b.dependency("translate_c", .{}), .{
        .name = "zstd",
        .c_source_file = b.path("build/zstd.h"),
        .target = module.resolved_target.?,
        .optimize = module.optimize.?,
        // Aro's builtin headers provide size_t without consulting system libc
        // headers or making the headers-only guest graphs link libc.
        .link_libc = false,
    });
    translator.addIncludePath(dependency.path("lib"));
    module.addImport("zstd_c", translator.mod);
}

pub fn addLibrary(module: *std.Build.Module, dependency: *std.Build.Dependency) void {
    addHeaders(module, dependency);
    module.linkLibrary(dependency.artifact("zstd"));
}
