//! Versioned package-family boundary used by image builders.
//! Debian-family roots are delegated to debz; existing RPM customization
//! remains behind the caller-supplied backend and is not changed here.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

pub const api_version: u32 = 1;
pub const request_schema = "io.github.cataggar.zvmi.package-family.request.v1";
pub const result_schema = "io.github.cataggar.zvmi.package-family.result.v1";

pub const Family = enum { rpm, debian };
pub const Distribution = enum { azure_linux, ubuntu_26_04, debian };
pub const Architecture = enum {
    amd64,
    arm64,

    fn debzName(self: Architecture) []const u8 {
        return @tagName(self);
    }
};
pub const Operation = enum { create, customize, update, recover, inspect };
pub const CacheMode = enum { online, prefer_cache, offline };
pub const FailureDisposition = enum { disposable, recoverable };

pub const Inputs = struct {
    root_stage: []const u8,
    published_root: []const u8,
    architecture: Architecture,
    foreign_architectures: []const Architecture = &.{},
    source_paths: []const []const u8,
    keyring_paths: []const []const u8,
    config_paths: []const []const u8 = &.{},
    cache_path: []const u8,
    state_path: []const u8,
    lock_input_path: ?[]const u8 = null,
    lock_output_path: ?[]const u8 = null,
    credential_reference: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    cache_mode: CacheMode = .online,
    recommends: bool = false,
    allow_downgrade: bool = false,
    deadline_ms: u64 = 300_000,
    lock_wait_ms: u64 = 30_000,
};

pub const Request = struct {
    schema: []const u8 = request_schema,
    version: u32 = api_version,
    family: Family,
    distribution: Distribution,
    operation: Operation,
    package: ?[]const u8 = null,
    inputs: Inputs,
};

pub const DiagnosticId = enum {
    invalid_request,
    unsupported_family,
    unsupported_distribution,
    backend_unavailable,
    backend_failed,
    lock_missing,
    provenance_missing,
    publication_failed,
};

pub const Diagnostic = struct {
    id: DiagnosticId,
    message: []const u8,
    disposition: FailureDisposition,
    backend_exit_code: ?u8 = null,
};

pub const Result = struct {
    schema: []const u8 = result_schema,
    version: u32 = api_version,
    succeeded: bool,
    published: bool,
    lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    diagnostic: ?Diagnostic = null,
};

pub const RunResult = struct {
    exit_code: u8,
};

pub const Runner = struct {
    context: ?*anyopaque,
    runFn: *const fn (?*anyopaque, Allocator, Io, []const []const u8) anyerror!RunResult,

    pub fn run(self: Runner, allocator: Allocator, io: Io, argv: []const []const u8) !RunResult {
        return self.runFn(self.context, allocator, io, argv);
    }
};

pub const SystemRunner = struct {
    pub fn interface(self: *SystemRunner) Runner {
        return .{ .context = self, .runFn = run };
    }

    fn run(_: ?*anyopaque, _: Allocator, io: Io, argv: []const []const u8) !RunResult {
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
        });
        defer child.kill(io);
        return switch (try child.wait(io)) {
            .exited => |code| .{ .exit_code = @intCast(@min(code, 255)) },
            else => .{ .exit_code = 70 },
        };
    }
};

pub const ExistingBackend = struct {
    context: ?*anyopaque,
    executeFn: *const fn (?*anyopaque, Allocator, Io, Request) anyerror!Result,
};

pub const BackendSet = struct {
    debz_path: []const u8 = "debz",
    runner: Runner,
    rpm: ?ExistingBackend = null,
};

pub fn execute(
    allocator: Allocator,
    io: Io,
    backends: BackendSet,
    request: Request,
) !Result {
    if (!valid(request))
        return failed(.invalid_request, "invalid explicit package-family request", .disposable, null);
    if (request.family == .rpm) {
        const backend = backends.rpm orelse
            return failed(.unsupported_family, "RPM package-family backend is not configured", .disposable, null);
        return backend.executeFn(backend.context, allocator, io, request);
    }
    if (request.distribution != .ubuntu_26_04 and request.distribution != .debian)
        return failed(.unsupported_distribution, "debz supports Ubuntu and Debian roots only", .disposable, null);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const argv = try debzArgv(arena, backends.debz_path, request);
    const run = backends.runner.run(arena, io, argv) catch
        return failed(.backend_unavailable, "debz package-family backend could not be started", .disposable, null);
    if (run.exit_code != 0) {
        const disposition: FailureDisposition = if (run.exit_code == 7 or run.exit_code == 8)
            .recoverable
        else
            .disposable;
        if (disposition == .disposable)
            Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
        return failed(.backend_failed, "debz package-family transaction failed", disposition, run.exit_code);
    }

    const lock_path = request.inputs.lock_output_path orelse request.inputs.lock_input_path;
    if (request.operation != .inspect and lock_path == null) {
        Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
        return failed(.lock_missing, "successful package transaction did not declare an exact lock", .disposable, 0);
    }
    if (lock_path) |path| {
        _ = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch {
            Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
            return failed(.lock_missing, "debz did not emit or preserve the exact lock", .disposable, 0);
        };
    }
    const provenance_path = if (mutates(request.operation))
        try std.fmt.allocPrint(allocator, "{s}/transaction-result.json", .{request.inputs.state_path})
    else
        null;
    errdefer if (provenance_path) |path| allocator.free(path);
    if (provenance_path) |path| {
        _ = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch {
            return failed(.provenance_missing, "debz did not emit transaction provenance", .recoverable, 0);
        };
    }

    if (request.operation != .inspect and request.operation != .recover) {
        Dir.renamePreserve(
            Dir.cwd(),
            request.inputs.root_stage,
            Dir.cwd(),
            request.inputs.published_root,
            io,
        ) catch {
            return failed(.publication_failed, "validated root could not be published atomically", .recoverable, 0);
        };
    }
    return .{
        .succeeded = true,
        .published = request.operation != .inspect and request.operation != .recover,
        .lock_path = lock_path,
        .provenance_path = provenance_path,
    };
}

fn debzArgv(allocator: Allocator, executable: []const u8, request: Request) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(allocator, executable);
    try argv.append(allocator, switch (request.operation) {
        .create, .customize => "install",
        .update => if (request.package == null) "upgrade-all" else "upgrade",
        .recover => "recover",
        .inspect => "list-installed",
    });
    try pair(&argv, allocator, "--install-root", request.inputs.root_stage);
    try pair(&argv, allocator, "--architecture", request.inputs.architecture.debzName());
    for (request.inputs.foreign_architectures) |architecture|
        try pair(&argv, allocator, "--foreign-architecture", architecture.debzName());
    try pair(&argv, allocator, "--cache-path", request.inputs.cache_path);
    try pair(&argv, allocator, "--state-path", request.inputs.state_path);
    for (request.inputs.source_paths) |path| try pair(&argv, allocator, "--source", path);
    for (request.inputs.config_paths) |path| try pair(&argv, allocator, "--config", path);
    for (request.inputs.keyring_paths) |path| try pair(&argv, allocator, "--keyring", path);
    if (request.inputs.lock_input_path) |path| try pair(&argv, allocator, "--lock-input", path);
    if (request.inputs.lock_output_path) |path| try pair(&argv, allocator, "--lock-output", path);
    if (request.inputs.credential_reference) |path| try pair(&argv, allocator, "--credential-reference", path);
    if (request.inputs.proxy) |value| try pair(&argv, allocator, "--proxy", value);
    try pair(&argv, allocator, "--deadline-ms", try std.fmt.allocPrint(allocator, "{d}", .{request.inputs.deadline_ms}));
    try pair(&argv, allocator, "--lock-wait-ms", try std.fmt.allocPrint(allocator, "{d}", .{request.inputs.lock_wait_ms}));
    if (request.inputs.cache_mode == .offline) try argv.append(allocator, "--cache-only");
    if (request.inputs.recommends) try argv.append(allocator, "--recommends");
    if (request.inputs.allow_downgrade) try argv.append(allocator, "--allow-downgrade");
    if (mutates(request.operation)) {
        try argv.appendSlice(allocator, &.{ "--assume-yes", "--noninteractive", "--conffile", "keep-existing", "--json" });
    } else {
        try argv.append(allocator, "--json");
    }
    if (request.package) |package| try argv.append(allocator, package);
    return argv.toOwnedSlice(allocator);
}

fn pair(argv: *std.ArrayList([]const u8), allocator: Allocator, name: []const u8, value: []const u8) !void {
    try argv.appendSlice(allocator, &.{ name, value });
}

fn valid(request: Request) bool {
    if (!std.mem.eql(u8, request.schema, request_schema) or request.version != api_version) return false;
    if (!absolute(request.inputs.root_stage) or !absolute(request.inputs.published_root) or
        !absolute(request.inputs.cache_path) or !absolute(request.inputs.state_path)) return false;
    if (std.mem.eql(u8, request.inputs.root_stage, request.inputs.published_root)) return false;
    if (request.inputs.source_paths.len == 0 or request.inputs.keyring_paths.len == 0) return false;
    for (request.inputs.source_paths) |path| if (!absolute(path)) return false;
    for (request.inputs.config_paths) |path| if (!absolute(path)) return false;
    for (request.inputs.keyring_paths) |path| if (!absolute(path)) return false;
    for (request.inputs.foreign_architectures) |architecture|
        if (architecture == request.inputs.architecture) return false;
    if ((request.operation == .create or request.operation == .customize) and request.package == null) return false;
    if (request.operation == .recover and request.inputs.lock_input_path == null) return false;
    if (request.inputs.lock_output_path != null and request.inputs.lock_input_path == null) return false;
    return true;
}

fn mutates(operation: Operation) bool {
    return operation != .inspect;
}

fn absolute(path: []const u8) bool {
    return path.len > 1 and path[0] == '/' and path[path.len - 1] != '/';
}

fn failed(
    id: DiagnosticId,
    message: []const u8,
    disposition: FailureDisposition,
    exit_code: ?u8,
) Result {
    return .{
        .succeeded = false,
        .published = false,
        .diagnostic = .{
            .id = id,
            .message = message,
            .disposition = disposition,
            .backend_exit_code = exit_code,
        },
    };
}

const FakeRunner = struct {
    exit_code: u8 = 0,
    state_path: []const u8,
    lock_path: []const u8,
    expected_verb: ?[]const u8 = null,

    fn run(context: ?*anyopaque, _: Allocator, io: Io, argv: []const []const u8) !RunResult {
        const self: *FakeRunner = @ptrCast(@alignCast(context.?));
        if (self.expected_verb) |verb| try std.testing.expectEqualStrings(verb, argv[1]);
        for (argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "apt"));
            try std.testing.expect(!std.mem.eql(u8, arg, "apt-get"));
        }
        if (self.exit_code == 0) {
            var lock = try Dir.cwd().createFile(io, self.lock_path, .{});
            lock.close(io);
            const provenance = try std.fmt.allocPrint(std.testing.allocator, "{s}/transaction-result.json", .{self.state_path});
            defer std.testing.allocator.free(provenance);
            var file = try Dir.cwd().createFile(io, provenance, .{});
            file.close(io);
        }
        return .{ .exit_code = self.exit_code };
    }
};

test "Ubuntu amd64 and arm64 roots publish only after lock and provenance" {
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    inline for (.{ Architecture.amd64, Architecture.arm64 }) |architecture| {
        const suffix = @tagName(architecture);
        const stage_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}-stage", .{suffix});
        defer std.testing.allocator.free(stage_name);
        const stage = try std.fs.path.join(std.testing.allocator, &.{ cwd, stage_name });
        defer std.testing.allocator.free(stage);
        const output_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}-root", .{suffix});
        defer std.testing.allocator.free(output_name);
        const output = try std.fs.path.join(std.testing.allocator, &.{ cwd, output_name });
        defer std.testing.allocator.free(output);
        const state_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}-state", .{suffix});
        defer std.testing.allocator.free(state_name);
        const state = try std.fs.path.join(std.testing.allocator, &.{ cwd, state_name });
        defer std.testing.allocator.free(state);
        const lock_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}.lock", .{suffix});
        defer std.testing.allocator.free(lock_name);
        const lock = try std.fs.path.join(std.testing.allocator, &.{ cwd, lock_name });
        defer std.testing.allocator.free(lock);
        defer Dir.cwd().deleteTree(io, output) catch {};
        defer Dir.cwd().deleteTree(io, stage) catch {};
        defer Dir.cwd().deleteTree(io, state) catch {};
        defer Dir.cwd().deleteFile(io, lock) catch {};
        try Dir.cwd().createDir(io, stage, .default_dir);
        try Dir.cwd().createDir(io, state, .default_dir);
        var runner: FakeRunner = .{ .state_path = state, .lock_path = lock };
        const result = try execute(std.testing.allocator, io, .{
            .runner = .{ .context = &runner, .runFn = FakeRunner.run },
        }, .{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = .create,
            .package = "ubuntu-minimal",
            .inputs = .{
                .root_stage = stage,
                .published_root = output,
                .architecture = architecture,
                .foreign_architectures = if (architecture == .amd64) &.{.arm64} else &.{.amd64},
                .source_paths = &.{"/inputs/ubuntu.sources"},
                .keyring_paths = &.{"/inputs/ubuntu.gpg"},
                .cache_path = "/cache/debz",
                .state_path = state,
                .lock_input_path = lock,
                .cache_mode = .offline,
            },
        });
        defer if (result.provenance_path) |path| std.testing.allocator.free(path);
        try std.testing.expect(result.succeeded);
        try std.testing.expect(result.published);
        _ = try Dir.cwd().statFile(io, output, .{});
    }
}

test "customization and update replay one exact lock deterministically" {
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const state = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-repeat-state" });
    defer std.testing.allocator.free(state);
    const lock = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-repeat.lock" });
    defer std.testing.allocator.free(lock);
    defer Dir.cwd().deleteTree(io, state) catch {};
    defer Dir.cwd().deleteFile(io, lock) catch {};
    try Dir.cwd().createDir(io, state, .default_dir);

    inline for (.{ Operation.customize, Operation.update }) |operation| {
        const name = @tagName(operation);
        const stage_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}-stage", .{name});
        defer std.testing.allocator.free(stage_name);
        const stage = try std.fs.path.join(std.testing.allocator, &.{ cwd, stage_name });
        defer std.testing.allocator.free(stage);
        const output_name = try std.fmt.allocPrint(std.testing.allocator, ".test-ubuntu-{s}-root", .{name});
        defer std.testing.allocator.free(output_name);
        const output = try std.fs.path.join(std.testing.allocator, &.{ cwd, output_name });
        defer std.testing.allocator.free(output);
        defer Dir.cwd().deleteTree(io, stage) catch {};
        defer Dir.cwd().deleteTree(io, output) catch {};
        try Dir.cwd().createDir(io, stage, .default_dir);

        var runner: FakeRunner = .{
            .state_path = state,
            .lock_path = lock,
            .expected_verb = if (operation == .customize) "install" else "upgrade-all",
        };
        const result = try execute(std.testing.allocator, io, .{
            .runner = .{ .context = &runner, .runFn = FakeRunner.run },
        }, .{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = operation,
            .package = if (operation == .customize) "cloud-init" else null,
            .inputs = .{
                .root_stage = stage,
                .published_root = output,
                .architecture = .amd64,
                .foreign_architectures = &.{.arm64},
                .source_paths = &.{"/inputs/ubuntu.sources"},
                .keyring_paths = &.{"/inputs/ubuntu.gpg"},
                .cache_path = "/cache/debz",
                .state_path = state,
                .lock_input_path = lock,
                .cache_mode = .offline,
            },
        });
        defer if (result.provenance_path) |path| std.testing.allocator.free(path);
        try std.testing.expect(result.succeeded);
        try std.testing.expectEqualStrings(lock, result.lock_path.?);
    }
}

test "dpkg failure retains a recoverable stage and never publishes" {
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const stage = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-recovery-stage" });
    defer std.testing.allocator.free(stage);
    const output = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-recovery-root" });
    defer std.testing.allocator.free(output);
    const state = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-recovery-state" });
    defer std.testing.allocator.free(state);
    const lock = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-recovery.lock" });
    defer std.testing.allocator.free(lock);
    defer Dir.cwd().deleteTree(io, stage) catch {};
    defer Dir.cwd().deleteTree(io, output) catch {};
    defer Dir.cwd().deleteTree(io, state) catch {};
    try Dir.cwd().createDir(io, stage, .default_dir);
    try Dir.cwd().createDir(io, state, .default_dir);
    var runner: FakeRunner = .{ .exit_code = 7, .state_path = state, .lock_path = lock };
    const result = try execute(std.testing.allocator, io, .{
        .runner = .{ .context = &runner, .runFn = FakeRunner.run },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .update,
        .inputs = .{
            .root_stage = stage,
            .published_root = output,
            .architecture = .arm64,
            .foreign_architectures = &.{.amd64},
            .source_paths = &.{"/inputs/ubuntu.sources"},
            .keyring_paths = &.{"/inputs/ubuntu.gpg"},
            .cache_path = "/cache/debz",
            .state_path = state,
            .lock_input_path = lock,
        },
    });
    try std.testing.expect(!result.succeeded);
    try std.testing.expectEqual(FailureDisposition.recoverable, result.diagnostic.?.disposition);
    _ = try Dir.cwd().statFile(io, stage, .{});
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, output, .{}));
}

test "backend failures never publish partial roots" {
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const stage = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-fail-stage" });
    defer std.testing.allocator.free(stage);
    const output = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-fail-root" });
    defer std.testing.allocator.free(output);
    const state = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-fail-state" });
    defer std.testing.allocator.free(state);
    const lock = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".test-ubuntu-fail.lock" });
    defer std.testing.allocator.free(lock);
    defer Dir.cwd().deleteTree(io, stage) catch {};
    defer Dir.cwd().deleteTree(io, output) catch {};
    defer Dir.cwd().deleteTree(io, state) catch {};
    try Dir.cwd().createDir(io, stage, .default_dir);
    try Dir.cwd().createDir(io, state, .default_dir);
    var runner: FakeRunner = .{ .exit_code = 6, .state_path = state, .lock_path = lock };
    const result = try execute(std.testing.allocator, io, .{
        .runner = .{ .context = &runner, .runFn = FakeRunner.run },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .create,
        .package = "ubuntu-minimal",
        .inputs = .{
            .root_stage = stage,
            .published_root = output,
            .architecture = .amd64,
            .source_paths = &.{"/inputs/ubuntu.sources"},
            .keyring_paths = &.{"/inputs/ubuntu.gpg"},
            .cache_path = "/cache/debz",
            .state_path = state,
            .lock_input_path = lock,
        },
    });
    try std.testing.expect(!result.succeeded);
    try std.testing.expect(!result.published);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, output, .{}));
}
