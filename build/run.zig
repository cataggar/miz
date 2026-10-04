const std = @import("std");

pub const EnvironmentPath = struct {
    name: []const u8,
    path: std.Build.LazyPath,
};

pub fn addArtifactWithEnvironmentPaths(
    b: *std.Build,
    artifact: *std.Build.Step.Compile,
    paths: []const EnvironmentPath,
) *std.Build.Step.Run {
    const run = b.addRunArtifact(artifact);
    const args = run.argv.toOwnedSlice(b.allocator) catch @panic("OOM");
    // Installation prefixes are resolved during make, and Run environment
    // values cannot contain LazyPaths. `env` preserves the test-server stdio
    // protocol while supplying absolute, content-tracked runtime paths.
    run.addArg("env");
    for (paths) |entry| {
        run.addFileArg2(entry.path, .{
            .prefix = b.fmt("{s}=", .{entry.name}),
            .make_absolute = true,
        });
    }
    run.argv.appendSlice(b.allocator, args) catch @panic("OOM");
    return run;
}
