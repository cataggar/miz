//! Host-only RPM package-family adapter.
//!
//! The core package-family types remain dependency-free so guest and init
//! static modules never import rpmz. Build consumers import this module as
//! `vmiz-package-family-host`.

const std = @import("std");
const core = @import("package_family");
const rpmz = @import("rpmz");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

pub const package_family = core;
pub const rpmz_commit = core.rpmz_api_commit;

pub fn execute(
    allocator: Allocator,
    io: Io,
    backends: core.BackendSet,
    request: core.Request,
) !core.Result {
    var selected = backends;
    selected.rpmz = .{ .context = null, .executeFn = executeRpmz };
    return core.execute(allocator, io, selected, request);
}

fn replayDiagnostic(
    validation: ?rpmz.replay.ValidationFailure,
    transaction: ?rpmz.replay.TransactionFailure,
) core.DiagnosticId {
    if (validation) |reason| return switch (reason) {
        .rpmdb_mismatch, .prior_mismatch => .rpmdb_mismatch,
        .checksum_mismatch,
        .size_mismatch,
        .manifest_not_canonical,
        .missing_bundle_file,
        .additional_bundle_file,
        .unsafe_bundle_entry,
        .plan_mismatch,
        .repository_mismatch,
        .metadata_mismatch,
        .rpm_mismatch,
        .signature_mismatch,
        .non_replayable_bundle,
        => .bundle_invalid,
        else => .backend_failed,
    };
    if (transaction == .expected_inventory_mismatch) return .inventory_mismatch;
    return .backend_failed;
}

fn executeRpmz(
    context: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    request: core.Request,
) !core.Result {
    return executeRpmzImpl(context, allocator, io, request) catch
        failure(.backend_failed, "rpmz adapter infrastructure failed", .disposable);
}

fn executeRpmzImpl(
    _: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    request: core.Request,
) !core.Result {
    const options = request.inputs.rpm orelse
        return failure(.invalid_request, "rpmz inputs are required", .disposable);
    if (options.import_trust)
        return failure(.unsupported_operation, "rpmz replay does not publicly support target trust import", .disposable);
    if (request.inputs.config_paths.len != 0)
        return failure(.unsupported_operation, "arbitrary RPM configuration files cannot be translated to rpmz typed inputs", .disposable);
    if (request.inputs.foreign_architectures.len != 0)
        return failure(.unsupported_operation, "rpmz replay does not expose foreign-architecture target configuration", .disposable);
    if (request.inputs.credential_reference != null or request.inputs.proxy != null)
        return failure(.unsupported_operation, "credential references and proxy policy are not exposed by rpmz replay", .disposable);
    if (request.operation == .recover or request.operation == .inspect)
        return failure(.unsupported_operation, "operation is not supported by rpmz public replay", .disposable);
    if (request.operation == .resolve_lock and options.bundle_input_path != null)
        return failure(.unsupported_operation, "resolve-lock requires a new explicit bundle export", .disposable);
    if (options.actions.len != 1)
        return failure(.unsupported_operation, "rpmz bundles contain exactly one explicit transaction", .disposable);
    if (!operationMatchesAction(request.operation, options.actions[0]))
        return failure(.unsupported_operation, "RPM action does not match the requested operation", .disposable);
    if (request.operation != .resolve_lock and options.exact_lock.len == 0)
        return failure(.lock_missing, "mutating RPM operations require an exact final inventory lock", .disposable);
    if (options.bundle_input_path == null and options.exact_lock.len != 0 and
        options.actions[0] == .update_all)
        return failure(.unsupported_operation, "rpmz resolver cannot express an exact update-all lock", .disposable);
    if (options.bundle_input_path == null and request.inputs.cache_mode == .offline) {
        for (options.repositories) |repository| if (repository.local_snapshot == null)
            return failure(.unsupported_operation, "offline planning requires declared local repository snapshots", .disposable);
    }
    if (options.bundle_input_path == null and !std.mem.eql(u8, options.rpmdb_path, "/var/lib/rpm"))
        return failure(.unsupported_operation, "rpmz resolver does not expose a non-default rpmdb path", .disposable);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bundle = if (options.bundle_input_path) |path|
        path
    else blk: {
        const destination = options.bundle_output_path orelse
            return failure(.lock_missing, "rpmz planning requires an explicit bundle output", .disposable);
        const resolve = resolveInput(arena, request, options) catch |err| switch (err) {
            error.ExactLockMissing => return failure(.lock_missing, "an RPM action is not covered by the exact lock", .disposable),
            else => return err,
        };
        var exported = rpmz.bundle_export.exportBundle(allocator, io, .{
            .resolve = resolve,
            .destination = destination,
            .keys = try keyInputs(arena, options.repositories),
            .gpg_check = options.gpg_check,
        }) catch
            return failure(.backend_failed, "rpmz bundle export failed", .disposable);
        defer exported.deinit();
        switch (exported) {
            .problems => |plan| return solverFailure(plan.model().problems.len),
            .exported => {},
        }
        break :blk destination;
    };
    const opened_bundle = rpmz.bundle_reader.openBundle(allocator, io, bundle) catch
        return failure(.bundle_invalid, "rpmz bundle preflight failed", .disposable);
    defer opened_bundle.destroy();
    if (!repositoriesMatch(options.repositories, opened_bundle.model().repositories))
        return failure(.bundle_invalid, "rpmz bundle repository identity does not match the request", .disposable);
    const plan_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ bundle, opened_bundle.model().plan.path },
    );
    defer allocator.free(plan_path);
    const plan_bytes = try readRegularFile(allocator, io, plan_path, 16 << 20);
    defer allocator.free(plan_bytes);
    const plan = rpmz.transaction_plan.parse(allocator, plan_bytes) catch
        return failure(.bundle_invalid, "rpmz bundle plan is invalid", .disposable);
    defer plan.destroy();
    if (!planMatchesRequest(plan.model(), request, options.actions[0]))
        return failure(.bundle_invalid, "rpmz bundle plan identity does not match the request", .disposable);
    const bundle_digest = try opened_bundle.digest(allocator);

    if (request.operation == .resolve_lock) {
        return .{
            .succeeded = true,
            .published = false,
            .lock_path = bundle,
        };
    }

    const architecture = rpmArchitecture(request.inputs.architecture);
    const replay = try rpmz.replay.run(allocator, io, .{
        .bundle_directory = bundle,
        .target = .{
            .install_root = request.inputs.root_stage,
            .rpmdb_path = options.rpmdb_path,
            .architecture = architecture,
        },
    });
    defer replay.deinit();

    if (replay.status != .succeeded) {
        const diagnostic = replayDiagnostic(
            replay.validation_failure,
            replay.transaction_failure,
        );
        Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
        return failure(diagnostic, "rpmz exact offline replay failed", .disposable);
    }
    if (replay.final_inventory == null or replay.applied_plan_digest == null) {
        Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
        return failure(.inventory_mismatch, "rpmz did not verify the final inventory", .disposable);
    }
    if (!inventoryMatches(options.exact_lock, replay.final_inventory.?)) {
        Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
        return failure(.inventory_mismatch, "final RPM inventory does not satisfy the vmiz exact lock", .disposable);
    }

    Dir.cwd().createDir(io, request.inputs.state_path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const provenance_path = try std.fmt.allocPrint(
        allocator,
        "{s}/transaction-result.json",
        .{request.inputs.state_path},
    );
    errdefer allocator.free(provenance_path);
    const replay_json = try replay.canonicalJsonAlloc(allocator);
    defer allocator.free(replay_json);
    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"backend\":\"rpmz\",\"backend_commit\":\"{s}\",\"bundle_digest\":\"{s}\",\"replay\":{s},\"schema\":\"{s}\"}}",
        .{ core.rpmz_api_commit, &bundle_digest, replay_json, core.rpm_provenance_schema },
    );
    defer allocator.free(json);
    try writeAtomically(allocator, io, provenance_path, json);

    const lock_path = if (request.inputs.lock_output_path) |path| blk: {
        const lock_json = try std.json.Stringify.valueAlloc(allocator, .{
            .architecture = rpmArchitecture(request.inputs.architecture),
            .bundle_digest = &bundle_digest,
            .bundle_directory = bundle,
            .distro = options.distro,
            .exact_inventory = options.exact_lock,
            .plan_digest = replay.applied_plan_digest.?,
            .release_version = options.release_version,
            .rpmz_commit = core.rpmz_api_commit,
            .schema = core.rpm_lock_schema,
        }, .{});
        defer allocator.free(lock_json);
        try writeAtomically(allocator, io, path, lock_json);
        break :blk path;
    } else unreachable;

    Dir.renamePreserve(
        Dir.cwd(),
        request.inputs.root_stage,
        Dir.cwd(),
        request.inputs.published_root,
        io,
    ) catch
        {
            Dir.cwd().deleteFile(io, provenance_path) catch {};
            if (request.inputs.lock_output_path) |path| Dir.cwd().deleteFile(io, path) catch {};
            return failure(.publication_failed, "validated RPM root could not be published atomically", .recoverable);
        };

    return .{
        .succeeded = true,
        .published = true,
        .lock_path = lock_path,
        .provenance_path = provenance_path,
    };
}

fn repositoriesMatch(
    requested: []const core.RpmRepository,
    bundled: anytype,
) bool {
    if (requested.len != bundled.len) return false;
    for (requested) |repository| {
        var match_index: ?usize = null;
        for (bundled, 0..) |candidate, index| {
            if (std.mem.eql(u8, repository.id, candidate.id)) {
                match_index = index;
                break;
            }
        }
        const candidate = bundled[match_index orelse return false];
        if (repository.priority != candidate.priority or
            repository.gpg_check != candidate.gpg_check) return false;
        const expected_sources = if (repository.local_snapshot == null)
            repository.base_urls
        else
            &.{};
        if (expected_sources.len != candidate.sources.len) return false;
        for (expected_sources) |expected| {
            var found = false;
            for (candidate.sources) |actual| {
                if (std.mem.eql(u8, expected, actual)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
    }
    return true;
}

fn planMatchesRequest(
    plan: *const rpmz.transaction_plan.Data,
    request: core.Request,
    action: core.RpmAction,
) bool {
    const environment = plan.environment;
    if (!std.mem.eql(u8, environment.architecture, rpmArchitecture(request.inputs.architecture)) or
        !std.mem.eql(u8, environment.distro, request.inputs.rpm.?.distro) or
        !std.mem.eql(u8, environment.releasever, request.inputs.rpm.?.release_version)) return false;
    const expected_kind: rpmz.transaction_plan.RequestKind = switch (action) {
        .install => .install,
        .remove => .erase,
        .update_all => .update_all,
        .update_selected => .update,
    };
    if (plan.requests.len == 0) return false;
    for (plan.requests) |item| if (item.kind != expected_kind) return false;
    return true;
}

fn operationMatchesAction(operation: core.Operation, action: core.RpmAction) bool {
    const action_tag = std.meta.activeTag(action);
    return switch (operation) {
        .resolve_lock => true,
        .create, .customize => action_tag == .install,
        .update => action_tag == .update_all or action_tag == .update_selected,
        .remove => action_tag == .remove,
        .recover, .inspect => false,
    };
}

fn readRegularFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    const stat = try Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.NotFile;
    var file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(maximum_bytes));
}

fn writeAtomically(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    bytes: []const u8,
) !void {
    const temporary = try std.fmt.allocPrint(allocator, "{s}.part", .{path});
    defer allocator.free(temporary);
    errdefer Dir.cwd().deleteFile(io, temporary) catch {};
    {
        var file = try Dir.cwd().createFile(io, temporary, .{
            .truncate = true,
            .exclusive = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
    }
    try Dir.cwd().rename(temporary, Dir.cwd(), path, io);
}

fn resolveInput(
    allocator: Allocator,
    request: core.Request,
    options: core.RpmOptions,
) !rpmz.resolver.ResolveInput {
    const repositories = try allocator.alloc(rpmz.resolver.Repository, options.repositories.len);
    for (options.repositories, repositories) |source, *target| {
        target.* = .{
            .id = source.id,
            .priority = source.priority,
            .metadata = if (source.local_snapshot) |path|
                .{ .local_snapshot = path }
            else
                .{ .remote = .{ .base_urls = source.base_urls } },
            .gpg_check = source.gpg_check,
            .gpg_keys = source.gpg_key_paths,
        };
    }
    const action = options.actions[0];
    const operation: rpmz.resolver.Operation = switch (action) {
        .install => .install,
        .remove => .erase,
        .update_all => .upgrade_all,
        .update_selected => .upgrade,
    };
    const raw_subjects: []const []const u8 = switch (action) {
        .install => |values| values,
        .remove => |values| values,
        .update_all => &.{},
        .update_selected => |values| values,
    };
    const subjects = switch (action) {
        .install, .update_selected => try lockedSubjects(
            allocator,
            raw_subjects,
            options.exact_lock,
        ),
        else => raw_subjects,
    };
    return .{
        .operation = operation,
        .subjects = subjects,
        .repositories = repositories,
        .installed = .{ .install_root = request.inputs.root_stage },
        .environment = .{
            .architecture = rpmArchitecture(request.inputs.architecture),
            .distro = options.distro,
            .release_version = options.release_version,
        },
        .policy = .{ .allow_erasing = options.allow_erasing },
        .cache_dir = request.inputs.cache_path,
        .scratch_dir = options.scratch_path,
    };
}

fn lockedSubjects(
    allocator: Allocator,
    subjects: []const []const u8,
    locks: []const core.RpmPackageLock,
) ![]const []const u8 {
    if (locks.len == 0) return subjects;
    const result = try allocator.alloc([]const u8, subjects.len);
    for (subjects, result) |subject, *target| {
        const lock = findLock(locks, subject) orelse return error.ExactLockMissing;
        target.* = try std.fmt.allocPrint(
            allocator,
            "{s}-{s}.{s}",
            .{ lock.name, lock.evr, lock.architecture },
        );
    }
    return result;
}

fn findLock(locks: []const core.RpmPackageLock, name: []const u8) ?core.RpmPackageLock {
    for (locks) |lock| if (std.mem.eql(u8, lock.name, name)) return lock;
    return null;
}

fn inventoryMatches(
    locks: []const core.RpmPackageLock,
    inventory: []const rpmz.replay.InstalledPackage,
) bool {
    if (locks.len != inventory.len) return false;
    for (locks) |lock| {
        var found = false;
        for (inventory) |installed| {
            const identity = installed.identity;
            if (!std.mem.eql(u8, lock.name, identity.name) or
                !std.mem.eql(u8, lock.architecture, identity.arch)) continue;
            const colon = std.mem.indexOfScalar(u8, lock.evr, ':') orelse continue;
            const dash = std.mem.lastIndexOfScalar(u8, lock.evr, '-') orelse continue;
            if (dash <= colon + 1) continue;
            const epoch = std.fmt.parseInt(u32, lock.evr[0..colon], 10) catch continue;
            if (epoch != (identity.epoch orelse 0)) continue;
            if (!std.mem.eql(u8, lock.evr[colon + 1 .. dash], identity.version)) continue;
            if (!std.mem.eql(u8, lock.evr[dash + 1 ..], identity.release)) continue;
            found = true;
            break;
        }
        if (!found) return false;
    }
    return true;
}

fn keyInputs(
    allocator: Allocator,
    repositories: []const core.RpmRepository,
) ![]const rpmz.bundle_export.KeyInput {
    var count: usize = 0;
    for (repositories) |repository| count += repository.gpg_key_paths.len;
    const keys = try allocator.alloc(rpmz.bundle_export.KeyInput, count);
    var index: usize = 0;
    for (repositories) |repository| for (repository.gpg_key_paths) |path| {
        keys[index] = .{ .path = path };
        index += 1;
    };
    return keys;
}

fn rpmArchitecture(architecture: core.Architecture) []const u8 {
    return switch (architecture) {
        .amd64 => "x86_64",
        .arm64 => "aarch64",
    };
}

fn failure(
    id: core.DiagnosticId,
    message: []const u8,
    disposition: core.FailureDisposition,
) core.Result {
    return .{
        .succeeded = false,
        .published = false,
        .diagnostic = .{
            .id = id,
            .message = message,
            .disposition = disposition,
        },
    };
}

fn solverFailure(problem_count: usize) core.Result {
    var result = failure(
        .solver_contradiction,
        "rpmz solver reported structured contradictions",
        .disposable,
    );
    result.diagnostic.?.solver_problem_count = problem_count;
    return result;
}

test "rpmz is the default and legacy tdnf is explicit" {
    const Legacy = struct {
        fn run(_: ?*anyopaque, _: Allocator, _: Io, _: core.Request) !core.Result {
            return .{ .succeeded = true, .published = false };
        }
    };
    const base: core.Request = .{
        .family = .rpm,
        .distribution = .azure_linux,
        .operation = .update,
        .inputs = .{
            .root_stage = "/stage",
            .published_root = "/root",
            .architecture = .amd64,
            .source_paths = &.{},
            .keyring_paths = &.{},
            .cache_path = "/cache",
            .state_path = "/state",
            .lock_output_path = "/state/rpm.lock",
            .rpm = .{
                .repositories = &.{.{ .id = "base", .base_urls = &.{"https://example.invalid"} }},
                .actions = &.{.update_all},
                .distro = "azurelinux",
                .release_version = "3.0",
                .scratch_path = "/scratch",
                .bundle_input_path = "/bundle",
            },
        },
    };
    var default_request = base;
    const default_result = try core.execute(std.testing.allocator, std.testing.io, .{
        .legacy_rpm = .{ .context = null, .executeFn = Legacy.run },
    }, default_request);
    try std.testing.expectEqual(core.DiagnosticId.backend_unavailable, default_result.diagnostic.?.id);

    default_request.rpm_backend = .legacy_tdnf;
    const legacy_result = try core.execute(std.testing.allocator, std.testing.io, .{
        .legacy_rpm = .{ .context = null, .executeFn = Legacy.run },
    }, default_request);
    try std.testing.expect(legacy_result.succeeded);
}

test "install update and remove map to public resolver operations" {
    const options = core.RpmOptions{
        .repositories = &.{.{ .id = "base", .local_snapshot = "/repo" }},
        .actions = &.{.{ .install = &.{"app"} }},
        .distro = "azurelinux",
        .release_version = "3.0",
        .scratch_path = "/scratch",
        .exact_lock = &.{.{
            .name = "app",
            .evr = "0:1-1.azl3",
            .architecture = "x86_64",
        }},
    };
    const request: core.Request = .{
        .family = .rpm,
        .distribution = .azure_linux,
        .operation = .customize,
        .inputs = .{
            .root_stage = "/root",
            .published_root = "/published",
            .architecture = .amd64,
            .source_paths = &.{},
            .keyring_paths = &.{},
            .cache_path = "/cache",
            .state_path = "/state",
            .lock_output_path = "/state/rpm.lock",
            .rpm = options,
        },
    };
    const install = try resolveInput(std.testing.allocator, request, options);
    defer std.testing.allocator.free(install.repositories);
    defer std.testing.allocator.free(install.subjects);
    defer std.testing.allocator.free(install.subjects[0]);
    try std.testing.expectEqual(rpmz.resolver.Operation.install, install.operation);
    try std.testing.expectEqualStrings("app-0:1-1.azl3.x86_64", install.subjects[0]);
    try std.testing.expectEqualStrings("/repo", install.repositories[0].metadata.local_snapshot);

    var update_options = options;
    update_options.actions = &.{.{ .update_selected = &.{"app"} }};
    const update = try resolveInput(std.testing.allocator, request, update_options);
    defer std.testing.allocator.free(update.repositories);
    defer std.testing.allocator.free(update.subjects);
    defer std.testing.allocator.free(update.subjects[0]);
    try std.testing.expectEqual(rpmz.resolver.Operation.upgrade, update.operation);

    var remove_options = options;
    remove_options.actions = &.{.{ .remove = &.{"app"} }};
    const remove = try resolveInput(std.testing.allocator, request, remove_options);
    defer std.testing.allocator.free(remove.repositories);
    try std.testing.expectEqual(rpmz.resolver.Operation.erase, remove.operation);
    try std.testing.expectEqualStrings("app", remove.subjects[0]);
}

test "bundle tamper rpmdb drift and inventory mismatch remain distinct" {
    try std.testing.expectEqual(
        core.DiagnosticId.bundle_invalid,
        replayDiagnostic(.checksum_mismatch, null),
    );
    try std.testing.expectEqual(
        core.DiagnosticId.rpmdb_mismatch,
        replayDiagnostic(.rpmdb_mismatch, null),
    );
    try std.testing.expectEqual(
        core.DiagnosticId.inventory_mismatch,
        replayDiagnostic(null, .expected_inventory_mismatch),
    );
}

test "ambient repository configuration has no adapter input" {
    const fields = @typeInfo(rpmz.resolver.ResolveInput).@"struct".fields;
    inline for (fields) |field| {
        try std.testing.expect(!std.mem.eql(u8, field.name, "config_path"));
        try std.testing.expect(!std.mem.eql(u8, field.name, "repos_dir"));
    }
}

test "target trust import is explicitly unsupported" {
    const result = try execute(std.testing.allocator, std.testing.io, .{}, .{
        .family = .rpm,
        .distribution = .azure_linux,
        .operation = .update,
        .inputs = .{
            .root_stage = "/stage",
            .published_root = "/root",
            .architecture = .amd64,
            .source_paths = &.{},
            .keyring_paths = &.{},
            .cache_path = "/cache",
            .state_path = "/state",
            .lock_output_path = "/state/rpm.lock",
            .rpm = .{
                .repositories = &.{.{ .id = "base", .base_urls = &.{"https://example.invalid"} }},
                .actions = &.{.update_all},
                .distro = "azurelinux",
                .release_version = "3.0",
                .scratch_path = "/scratch",
                .bundle_input_path = "/bundle",
                .import_trust = true,
            },
        },
    });
    try std.testing.expectEqual(core.DiagnosticId.unsupported_operation, result.diagnostic.?.id);
}

test "unsupported replay operations are typed" {
    const result = try execute(std.testing.allocator, std.testing.io, .{}, .{
        .family = .rpm,
        .distribution = .azure_linux,
        .operation = .recover,
        .inputs = .{
            .root_stage = "/stage",
            .published_root = "/root",
            .architecture = .amd64,
            .source_paths = &.{},
            .keyring_paths = &.{},
            .cache_path = "/cache",
            .state_path = "/state",
            .lock_output_path = "/state/rpm.lock",
            .rpm = .{
                .repositories = &.{.{ .id = "base", .base_urls = &.{"https://example.invalid"} }},
                .actions = &.{.update_all},
                .distro = "azurelinux",
                .release_version = "3.0",
                .scratch_path = "/scratch",
                .bundle_input_path = "/bundle",
            },
        },
    });
    try std.testing.expectEqual(core.DiagnosticId.unsupported_operation, result.diagnostic.?.id);
    try std.testing.expect(!result.published);
}
