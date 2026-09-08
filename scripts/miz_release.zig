//! `miz_release`: fail-closed publication for the main miz release.

const std = @import("std");
const release = @import("release/root.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const usage =
    \\usage:
    \\  miz_release verify-version --tag TAG --manifest PATH [--github-output PATH]
    \\  miz_release check-release-policy --repository OWNER/REPO
    \\      --immutable-response PATH --rulesets-response PATH
    \\  miz_release publish --repository OWNER/REPO --tag TAG --version VERSION
    \\      --commit SHA --assets-directory PATH --workspace PATH
    \\      [--github-step-summary PATH]
    \\
;

const Options = struct {
    names: [16][]const u8 = undefined,
    values: [16][]const u8 = undefined,
    len: usize = 0,

    fn parse(argv: []const []const u8) !Options {
        var options: Options = .{};
        if (argv.len % 2 != 0) return error.Usage;
        var index: usize = 0;
        while (index < argv.len) : (index += 2) {
            if (!std.mem.startsWith(u8, argv[index], "--") or
                argv[index].len == 2 or options.len == options.names.len)
            {
                return error.Usage;
            }
            for (options.names[0..options.len]) |name| {
                if (std.mem.eql(u8, name, argv[index])) return error.Usage;
            }
            options.names[options.len] = argv[index];
            options.values[options.len] = argv[index + 1];
            options.len += 1;
        }
        return options;
    }

    fn get(self: *const Options, name: []const u8) ?[]const u8 {
        for (self.names[0..self.len], self.values[0..self.len]) |actual, value| {
            if (std.mem.eql(u8, actual, name)) return value;
        }
        return null;
    }

    fn require(self: *const Options, name: []const u8) ![]const u8 {
        return self.get(name) orelse error.Usage;
    }

    fn only(self: *const Options, allowed: []const []const u8) !void {
        for (self.names[0..self.len]) |actual| {
            var found = false;
            for (allowed) |name| {
                if (std.mem.eql(u8, actual, name)) found = true;
            }
            if (!found) return error.Usage;
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_file: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_file.interface;
    var diagnostic: release.Diagnostic = .{};

    run(
        allocator,
        io,
        init.environ_map.get("MIZ_GH") orelse "gh",
        init.minimal.environ,
        init.environ_map.get("MIZ_RELEASE_POLICY_GH_TOKEN"),
        argv[1..],
        &diagnostic,
    ) catch |err| switch (err) {
        error.Usage => {
            try stderr.writeAll(usage);
            try stderr.flush();
            std.process.exit(2);
        },
        error.Failed => {
            try stderr.print("{s}\n", .{diagnostic.message()});
            try stderr.flush();
            std.process.exit(1);
        },
        else => return err,
    };
}

fn run(
    allocator: Allocator,
    io: Io,
    gh_executable: []const u8,
    environment: std.process.Environ,
    policy_token: ?[]const u8,
    argv: []const []const u8,
    diagnostic: *release.Diagnostic,
) !void {
    if (argv.len == 0) return error.Usage;
    const options = try Options.parse(argv[1..]);
    if (std.mem.eql(u8, argv[0], "verify-version")) {
        try options.only(&.{ "--tag", "--manifest", "--github-output" });
        const version = try release.github_release.manifestVersion(
            allocator,
            io,
            try options.require("--manifest"),
            diagnostic,
        );
        defer allocator.free(version);
        const tag = try options.require("--tag");
        try release.github_release.validateVersionTag(version, tag, diagnostic);
        if (options.get("--github-output")) |output_path| {
            var output = try std.Io.Dir.cwd().openFile(io, output_path, .{
                .mode = .write_only,
            });
            defer output.close(io);
            const stat = try output.stat(io);
            var buffer: [512]u8 = undefined;
            const prerelease = std.mem.indexOfScalar(
                u8,
                std.mem.sliceTo(version, '+'),
                '-',
            ) != null;
            const text = try std.fmt.bufPrint(
                &buffer,
                "version={s}\nprerelease={s}\n",
                .{ version, if (prerelease) "true" else "false" },
            );
            try output.writePositionalAll(io, text, stat.size);
        }
        return;
    }
    if (std.mem.eql(u8, argv[0], "check-release-policy")) {
        try options.only(&.{
            "--repository",
            "--immutable-response",
            "--rulesets-response",
        });
        return release.github_release.validateRepositoryReleasePolicyFiles(
            allocator,
            io,
            try options.require("--immutable-response"),
            try options.require("--rulesets-response"),
            try options.require("--repository"),
            diagnostic,
        );
    }
    if (std.mem.eql(u8, argv[0], "publish")) {
        try options.only(&.{
            "--repository",
            "--tag",
            "--version",
            "--commit",
            "--assets-directory",
            "--workspace",
            "--github-step-summary",
        });
        return release.github_release.publish(allocator, io, .{
            .repository_name = try options.require("--repository"),
            .tag = try options.require("--tag"),
            .version = try options.require("--version"),
            .commit = try options.require("--commit"),
            .assets_directory = try options.require("--assets-directory"),
            .workspace = try options.require("--workspace"),
            .gh_executable = gh_executable,
            .summary_path = options.get("--github-step-summary"),
            .environment = environment,
            .policy_token = policy_token,
        }, diagnostic);
    }
    return error.Usage;
}

test "options reject duplicates and unknown values at the command boundary" {
    try std.testing.expectError(
        error.Usage,
        Options.parse(&.{ "--tag", "v1", "--tag", "v2" }),
    );
    const options = try Options.parse(&.{ "--tag", "v1" });
    try std.testing.expectError(
        error.Usage,
        options.only(&.{"--version"}),
    );
}
