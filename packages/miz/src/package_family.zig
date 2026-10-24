//! Versioned package-family boundary used by host-side image builders.
//! Debian-family roots use debz's native v2 package-family backend in-process
//! with exact-closure-lock-v3 and native-transaction-provenance-v2 without
//! invoking apt or dpkg; RPM behavior remains injectable.

const std = @import("std");
const debz = @import("debz");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

pub const api_version: u32 = 4;
pub const request_schema = "io.github.cataggar.miz.package-family.request.v4";
pub const result_schema = "io.github.cataggar.miz.package-family.result.v4";
pub const debz_commit = "a6c2732e2cab880b60a4affadb7e087bf007d1e8";
pub const debz_api_commit = debz_commit;
pub const debz_capability_schema = "io.github.cataggar.debz.package-family.capabilities.v2";
pub const debz_request_schema = "io.github.cataggar.debz.package-family.request.v2";
pub const debz_result_schema = "io.github.cataggar.debz.package-family.result.v2";
pub const debz_schema_version: u32 = 2;
pub const debz_exact_lock_schema = "https://debz.dev/schema/exact-closure-lock-v3";
pub const debz_provenance_schema = "https://debz.dev/schema/native-transaction-provenance-v2";
pub const rpmz_api_commit = "c9b23a2103b9682434ab663841d00cd657647561";
pub const rpm_lock_schema = "io.github.cataggar.miz.rpm-lock.v1";
pub const rpm_provenance_schema = "io.github.cataggar.miz.rpm-provenance.v1";

pub const Family = enum { rpm, debian };
pub const Distribution = enum { azure_linux, ubuntu_26_04, debian };
pub const RpmBackend = enum { rpmz, legacy_tdnf };
pub const Architecture = enum { amd64, arm64 };
pub const Operation = enum { resolve_lock, create, customize, update, remove, recover, inspect };
pub const CacheMode = enum { online, prefer_cache, offline };
pub const RepositoryPolicy = enum { strict_priority, best_version };
pub const ConffilePolicy = enum { keep_existing, use_package_version };
pub const InstalledBaselinePolicy = enum { none, require_locked };
pub const FailureDisposition = enum { disposable, recoverable };

pub const RpmRepository = struct {
    id: []const u8,
    base_urls: []const []const u8 = &.{},
    local_snapshot: ?[]const u8 = null,
    priority: i32 = 50,
    gpg_check: bool = true,
    gpg_key_paths: []const []const u8 = &.{},
};

pub const RpmAction = union(enum) {
    install: []const []const u8,
    remove: []const []const u8,
    update_all,
    update_selected: []const []const u8,
};

pub const RpmPackageLock = struct {
    name: []const u8,
    evr: []const u8,
    architecture: []const u8,
};

pub const RpmOptions = struct {
    repositories: []const RpmRepository,
    actions: []const RpmAction = &.{},
    distro: []const u8,
    release_version: []const u8,
    rpmdb_path: []const u8 = "/var/lib/rpm",
    scratch_path: []const u8,
    bundle_input_path: ?[]const u8 = null,
    bundle_output_path: ?[]const u8 = null,
    exact_lock: []const RpmPackageLock = &.{},
    import_trust: bool = false,
    allow_erasing: bool = false,
    gpg_check: bool = true,
};

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
    repository_policy: RepositoryPolicy = .strict_priority,
    recommends: bool = false,
    allow_downgrade: bool = false,
    conffile: ConffilePolicy = .keep_existing,
    installed_baseline: InstalledBaselinePolicy = .none,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
    now_unix: ?i64 = null,
    rpm: ?RpmOptions = null,
};

pub const Request = struct {
    schema: []const u8 = request_schema,
    version: u32 = api_version,
    family: Family,
    distribution: Distribution,
    operation: Operation,
    /// debz package-family schema v1 accepts at most one package. Requests
    /// containing more than one name are rejected rather than truncated.
    packages: []const []const u8 = &.{},
    rpm_backend: RpmBackend = .rpmz,
    inputs: Inputs,
};

pub const DiagnosticId = enum {
    invalid_request,
    unsupported_family,
    unsupported_distribution,
    unsupported_package_count,
    incompatible_backend,
    backend_unavailable,
    backend_failed,
    lock_missing,
    provenance_missing,
    publication_failed,
    unsupported_operation,
    solver_contradiction,
    bundle_invalid,
    rpmdb_mismatch,
    inventory_mismatch,
};

pub const Diagnostic = struct {
    id: DiagnosticId,
    message: []const u8,
    disposition: FailureDisposition,
    backend_exit_status: ?u8 = null,
    solver_problem_count: ?usize = null,
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

pub const ExistingBackend = struct {
    context: ?*anyopaque,
    executeFn: *const fn (?*anyopaque, Allocator, Io, Request) anyerror!Result,
};

/// Tests and specialized hosts can inject a typed debz product executor or
/// capability descriptor. The default runs debz.NativePackageFamilyBackend
/// with the caller's Io.
pub const DebianBackend = struct {
    capabilities: ?debz.NativePackageFamilyCapabilities = null,
    product_executor: ?debz.ProductBackend = null,
    now_unix: ?i64 = null,
};

pub fn defaultDebianCapabilities() debz.NativePackageFamilyCapabilities {
    return debz.nativePackageFamilyCapabilities();
}

pub const BackendSet = struct {
    debian: DebianBackend = .{},
    rpmz: ?ExistingBackend = null,
    legacy_rpm: ?ExistingBackend = null,
};

pub fn execute(
    allocator: Allocator,
    io: Io,
    backends: BackendSet,
    request: Request,
) !Result {
    if (invalidRequestMessage(request)) |message|
        return failed(.invalid_request, message, .disposable, null);
    if (request.family == .rpm) {
        const backend = switch (request.rpm_backend) {
            .rpmz => backends.rpmz orelse
                return failed(.backend_unavailable, "host rpmz package-family backend is not configured", .disposable, null),
            .legacy_tdnf => backends.legacy_rpm orelse
                return failed(.backend_unavailable, "legacy in-target tdnf/rpm backend is not configured", .disposable, null),
        };
        return backend.executeFn(backend.context, allocator, io, request);
    }
    if (request.operation == .remove)
        return failed(.unsupported_operation, "embedded debz does not expose package removal", .disposable, null);
    if (request.distribution != .ubuntu_26_04 and request.distribution != .debian)
        return failed(.unsupported_distribution, "debz supports Ubuntu and Debian roots only", .disposable, null);
    if (request.packages.len > 1)
        return failed(
            .unsupported_package_count,
            "debz package-family schema v1 accepts at most one package",
            .disposable,
            null,
        );
    const capabilities = backends.debian.capabilities orelse debz.nativePackageFamilyCapabilities();
    if (!compatible(capabilities))
        return failed(.incompatible_backend, "incompatible debz package-family capability schema", .disposable, null);

    var owned_result = executeDebz(allocator, io, backends.debian, request) catch {
        return failed(
            .backend_unavailable,
            "embedded debz backend could not execute",
            if (mutates(request.operation)) .recoverable else .disposable,
            null,
        );
    };
    defer owned_result.deinit();
    const backend_result = owned_result.result;
    if (!std.mem.eql(u8, backend_result.schema, debz_result_schema) or
        backend_result.version != debz_schema_version or
        backend_result.operation != debzOperation(request.operation))
    {
        cleanup(io, request);
        return failed(.incompatible_backend, "debz returned an incompatible result schema", .disposable, null);
    }
    if (!backend_result.succeeded) {
        const disposition: FailureDisposition = if (backend_result.diagnostic != null and
            backend_result.diagnostic.?.recoverable) .recoverable else .disposable;
        if (backend_result.diagnostic) |diagnostic| {
            const message = try debz.transaction_provenance.redactAlloc(allocator, diagnostic.message);
            defer allocator.free(message);
            std.debug.print("embedded debz backend {s}: {s}\n", .{ @tagName(diagnostic.id), message });
        }
        if (disposition == .disposable) cleanup(io, request);
        return failed(
            .backend_failed,
            "embedded debz package-family transaction failed",
            disposition,
            @backingInt(backend_result.exit_status),
        );
    }

    if (request.operation != .inspect and backend_result.lock_path == null) {
        cleanup(io, request);
        return failed(.lock_missing, "debz did not return an exact lock path", .disposable, 0);
    }
    var lock_digest: ?[32]u8 = null;
    const lock_path = if (backend_result.lock_path) |path| blk: {
        const expected = request.inputs.lock_output_path orelse request.inputs.lock_input_path;
        if (expected == null or !std.mem.eql(u8, path, expected.?)) {
            cleanup(io, request);
            return failed(.lock_missing, "debz returned an unexpected exact lock path", .disposable, 0);
        }
        lock_digest = verifyLock(
            allocator,
            io,
            path,
            request.inputs.architecture,
            request.inputs.installed_baseline,
        ) catch {
            cleanup(io, request);
            return failed(.lock_missing, "debz did not emit or preserve a valid exact lock", .disposable, 0);
        };
        break :blk expected.?;
    } else null;

    var published_provenance_path: ?[]u8 = null;
    errdefer if (published_provenance_path) |path| allocator.free(path);
    if (requiresProvenance(request.operation)) {
        const path = backend_result.provenance_path orelse
            return failed(.provenance_missing, "debz did not return transaction provenance", .recoverable, 0);
        const expected = try allocator.print("{s}/{s}", .{
            request.inputs.root_stage,
            debz.native_provenance.document_path,
        });
        defer allocator.free(expected);
        if (!std.mem.eql(u8, path, expected))
            return failed(.provenance_missing, "debz returned an unexpected provenance path", .recoverable, 0);
        const provenance_bytes = verifyProvenance(allocator, io, path, lock_digest.?) catch
            return failed(.provenance_missing, "debz did not emit valid transaction provenance", .recoverable, 0);
        defer allocator.free(provenance_bytes);
        const state_provenance = try allocator.print("{s}/{s}", .{
            request.inputs.state_path,
            debz.package_family_backend.provenance_basename,
        });
        writeRegularFile(io, state_provenance, provenance_bytes) catch {
            allocator.free(state_provenance);
            return failed(.provenance_missing, "debz transaction provenance could not be recorded", .recoverable, 0);
        };
        published_provenance_path = state_provenance;
    }

    if (publishes(request.operation)) {
        const stage_debz_dir = try allocator.print("{s}/var/lib/debz", .{request.inputs.root_stage});
        defer allocator.free(stage_debz_dir);
        Dir.cwd().deleteTree(io, stage_debz_dir) catch {
            if (published_provenance_path) |path| allocator.free(path);
            return failed(.publication_failed, "validated root stage could not be scrubbed before publication", .recoverable, 0);
        };
        Dir.renamePreserve(
            Dir.cwd(),
            request.inputs.root_stage,
            Dir.cwd(),
            request.inputs.published_root,
            io,
        ) catch {
            if (published_provenance_path) |path| allocator.free(path);
            return failed(.publication_failed, "validated root could not be published atomically", .recoverable, 0);
        };
    }
    return .{
        .succeeded = true,
        .published = publishes(request.operation),
        .lock_path = lock_path,
        .provenance_path = published_provenance_path,
    };
}

/// Host-side separation assertion for resolve and customize dispatch. Returns
/// the first violation message, or null when the request is well formed and
/// every source, config, keyring, cache, state, and lock path is an absolute
/// path outside both `root_stage` and `published_root`. It reuses exactly the
/// boundary policy `execute` enforces, then additionally forbids inputs from
/// overlapping the publication root so a published guest can never mutate the
/// trusted host inputs (for example a keyring) after they are consumed. Hosts
/// assert this before every dispatch instead of duplicating path policy.
pub fn requestViolation(request: Request) ?[]const u8 {
    if (invalidRequestMessage(request)) |message| return message;
    if (request.family != .debian) return null;
    const published = request.inputs.published_root;
    if (overlaps(published, request.inputs.cache_path) or
        overlaps(published, request.inputs.state_path))
        return "package-family publication must not overlap cache or state";
    for (request.inputs.source_paths) |path|
        if (overlaps(published, path)) return "debian source paths must be outside publication";
    for (request.inputs.config_paths) |path|
        if (overlaps(published, path)) return "debian config paths must be outside publication";
    for (request.inputs.keyring_paths) |path|
        if (overlaps(published, path)) return "debian keyring paths must be outside publication";
    if (request.inputs.lock_input_path) |path|
        if (overlaps(published, path)) return "lock input must be outside publication";
    if (request.inputs.lock_output_path) |path|
        if (overlaps(published, path)) return "lock output must be outside publication";
    if (request.inputs.credential_reference) |path|
        if (overlaps(published, path)) return "credential reference must be outside publication";
    return null;
}

/// Shared normalized-path containment predicate. Exposed so hosts and tests
/// reuse the same overlap policy the boundary enforces instead of
/// reimplementing prefix arithmetic.
pub fn pathsOverlap(left: []const u8, right: []const u8) bool {
    return overlaps(left, right);
}

fn executeDebz(
    allocator: Allocator,
    io: Io,
    backend: DebianBackend,
    request: Request,
) !debz.PackageFamilyOwnedResult {
    const foreign_architectures = try debzArchitectures(allocator, request.inputs.foreign_architectures);
    defer allocator.free(foreign_architectures);
    const debz_request: debz.PackageFamilyRequest = .{
        .schema = debz_request_schema,
        .version = debz_schema_version,
        .operation = debzOperation(request.operation),
        .root = request.inputs.root_stage,
        .architecture = switch (request.inputs.architecture) {
            .amd64 => .amd64,
            .arm64 => .arm64,
        },
        .foreign_architectures = foreign_architectures,
        .sources = request.inputs.source_paths,
        .keyrings = request.inputs.keyring_paths,
        .configs = request.inputs.config_paths,
        .cache = request.inputs.cache_path,
        .state = request.inputs.state_path,
        .package = if (request.packages.len == 1) request.packages[0] else null,
        .lock_input = request.inputs.lock_input_path,
        .lock_output = request.inputs.lock_output_path,
        .cache_mode = switch (request.inputs.cache_mode) {
            .online => .online,
            .prefer_cache => .prefer_cache,
            .offline => .offline,
        },
        .repository_policy = switch (request.inputs.repository_policy) {
            .strict_priority => .strict_priority,
            .best_version => .best_version,
        },
        .recommends = request.inputs.recommends,
        .allow_downgrade = request.inputs.allow_downgrade,
        .conffile = switch (request.inputs.conffile) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
        },
        .credential_reference = request.inputs.credential_reference,
        .proxy = request.inputs.proxy,
        .deadline_ms = request.inputs.deadline_ms,
        .lock_wait_ms = request.inputs.lock_wait_ms,
    };
    if (backend.product_executor) |product| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        var legacy_request = debz_request;
        legacy_request.schema = debz.package_family_backend.request_schema;
        legacy_request.version = debz.package_family_backend.schema_version;
        const package_family: debz.PackageFamilyBackend = .{
            .product_backend = product,
            .legacy_execution_capable = true,
        };
        var result = try package_family.execute(owned, legacy_request);
        result.schema = debz_result_schema;
        result.version = debz_schema_version;
        if (result.provenance_path != null) {
            result.provenance_path = try std.fmt.allocPrint(
                owned,
                "{s}/{s}",
                .{ request.inputs.root_stage, debz.native_provenance.document_path },
            );
        }
        return .{ .result = result, .arena = arena };
    }
    const native_backend: debz.NativePackageFamilyBackend = .{
        .io = io,
        .now_unix = request.inputs.now_unix orelse backend.now_unix,
        .archive_digest_policy = .published_digests,
    };
    return executeNativeDebz(
        native_backend,
        allocator,
        debz_request,
        request.inputs.installed_baseline,
    );
}

fn executeNativeDebz(
    native_backend: debz.NativePackageFamilyBackend,
    allocator: Allocator,
    request: debz.PackageFamilyRequest,
    installed_baseline: InstalledBaselinePolicy,
) !debz.PackageFamilyOwnedResult {
    switch (request.operation) {
        .inspect => return native_backend.execute(allocator, request),
        .resolve_lock => {
            var resolved = try native_backend.execute(allocator, request);
            errdefer resolved.deinit();
            if (resolved.result.succeeded and
                installed_baseline == .none and
                request.package != null and
                !std.mem.eql(u8, request.package.?, "mawk"))
            {
                if (resolved.result.lock_path) |lock_path| {
                    try preferMawkOverGawkInFreshRootLock(
                        native_backend,
                        allocator,
                        request,
                        lock_path,
                    );
                }
            }
            return resolved;
        },
        .create, .customize, .update, .recover => {},
    }
    var arena: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var native_install: ?debz.product_api.NativeInstallEvidence = null;
    var native_completion: ?debz.product_api.NativeCompletionEvidence = null;
    var result: debz.PackageFamilyResult = output: {
        const product_operation: debz.ProductOperation = switch (request.operation) {
            .resolve_lock => .plan,
            .create, .customize => .install,
            .update => if (request.package == null) .upgrade_all else .upgrade,
            .recover => .recover,
            .inspect => .list_installed,
        };
        const packages: []const []const u8 = if (request.package) |package|
            try owned.dupe([]const u8, &.{package})
        else
            &.{};
        const offline = request.cache_mode == .offline;
        const foreign_architectures = try owned.alloc([]const u8, request.foreign_architectures.len);
        for (request.foreign_architectures, 0..) |architecture, index|
            foreign_architectures[index] = architecture.spelling();
        const product_request: debz.ProductRequest = .{
            .operation = product_operation,
            .packages = packages,
            .options = .{
                .install_root = request.root,
                .source_paths = request.sources,
                .config_paths = request.configs,
                .keyring_paths = request.keyrings,
                .cache_path = request.cache,
                .state_path = request.state,
                .architecture = request.architecture.spelling(),
                .foreign_architectures = foreign_architectures,
                .repository_policy = request.repository_policy,
                .proxy = request.proxy,
                .credential_reference = request.credential_reference,
                .lock_input_path = request.lock_input,
                .lock_output_path = request.lock_output,
                .offline = offline,
                .cache_only = offline,
                .recommends = request.recommends,
                .allow_downgrade = request.allow_downgrade,
                .deadline_ms = request.deadline_ms,
                .lock_wait_ms = request.lock_wait_ms,
                .assume_yes = product_operation.mutates(),
                .noninteractive = product_operation.mutates(),
                .conffile = request.conffile,
            },
        };
        const lock_path = if (request.lock_output orelse request.lock_input) |path|
            try owned.dupe(u8, path)
        else
            null;
        const provenance_path = if (request.operation != .resolve_lock)
            try std.fmt.allocPrint(owned, "{s}/{s}", .{ request.root, debz.native_provenance.document_path })
        else
            null;
        var native: debz.ProductionBackend = .{
            .io = native_backend.io,
            .transaction_backend = .native,
            .native_runtime_allocator = allocator,
            .now_unix = native_backend.now_unix,
            .native_archive_digest_policy = native_backend.archive_digest_policy,
        };
        const response = try debz.executeProductRequest(owned, product_request, native.interface());
        native_install = response.native_install;
        native_completion = response.native_completion;
        if (!consistentNativeDebzEvidence(product_request, response))
            break :output nativeDebzEvidenceFailure(request.operation, response.changed, "native package-family result evidence is inconsistent");
        if (response.exit_status != .success) {
            var failed_result = debzFamilyFailure(
                request.operation,
                response.exit_status,
                .backend_failed,
                response.summary,
                response.exit_status == .transaction or response.exit_status == .recovery,
            );
            failed_result.changed = response.changed;
            if (native_completion != null) failed_result.provenance_path = provenance_path;
            break :output failed_result;
        }
        if (response.changed and request.operation != .recover) {
            var verified = verifyCompletedProductSuccess(
                native_backend,
                allocator,
                request,
                product_request,
                native_completion.?,
            ) catch |err| {
                if (err == error.OutOfMemory) return err;
                break :output nativeDebzEvidenceFailure(
                    request.operation,
                    response.changed,
                    try std.fmt.allocPrint(owned, "native completion verification failed: {s}", .{@errorName(err)}),
                );
            };
            defer verified.deinit();
            if (native_install) |install|
                if (verified.summary.package_count != install.package_count)
                    break :output nativeDebzEvidenceFailure(request.operation, response.changed, "native completion package count differs from the returned install evidence");
        }
        break :output .{
            .operation = request.operation,
            .succeeded = true,
            .changed = response.changed,
            .exit_status = .success,
            .lock_path = lock_path,
            .provenance_path = if (native_completion != null) provenance_path else null,
        };
    };
    result.schema = debz_result_schema;
    result.version = debz_schema_version;
    return .{
        .result = result,
        .arena = arena,
        .native_install = native_install,
        .native_completion = native_completion,
        .native_inspection = null,
    };
}

fn verifyCompletedProductSuccess(
    native_backend: debz.NativePackageFamilyBackend,
    allocator: Allocator,
    original: debz.PackageFamilyRequest,
    product_request: debz.ProductRequest,
    returned: debz.product_api.NativeCompletionEvidence,
) !debz.NativePackageFamilyVerifiedCompletion {
    if (returned.outcome != .succeeded or returned.settlement != .cleared)
        return error.InvalidNativeFamilyCompletion;
    if (debz.product_api.validate(product_request) != null)
        return error.InvalidNativeFamilyVerificationRequest;
    const path = original.lock_input.?;
    var parent = try debz.root_fs.openAbsoluteRoot(native_backend.io, std.fs.path.dirname(path).?);
    defer parent.close();
    const store = try debz.exact_lock_v3.Store.init(native_backend.io, parent.root.dir, std.fs.path.basename(path));
    var lock = try store.read(allocator, debz.exact_lock_v3.maximum_document_bytes);
    defer lock.deinit();
    var root = try debz.root_fs.openAbsoluteRoot(native_backend.io, original.root);
    defer root.close();
    var locks: debz.root_operation.SystemLockBackend = .{ .allocator = allocator, .io = native_backend.io };
    var summary = debz.native_transaction_result.verifyForCaller(
        allocator,
        root.root,
        original.root,
        lock.lock,
        original.architecture.spelling(),
        .{
            .operation = product_request.operation,
            .request_sha256 = debz.production_backend.productRequestDigest(product_request),
            .policy_sha256 = debz.production_backend.planningPolicyDigest(.native, product_request.options),
            .foreign_architectures = product_request.options.foreign_architectures,
            .completion = returned,
            .archive_digest_policy = native_backend.archive_digest_policy,
        },
        locks.interface(),
    ) catch |err| switch (err) {
        error.CallerRequestMismatch => return error.NativeFamilyRequestMismatch,
        error.CompletionResultMismatch => return error.NativeFamilyCompletionMismatch,
        else => return err,
    };
    summary.install_root = try allocator.dupe(u8, summary.install_root);
    return .{ .summary = summary, .allocator = allocator };
}

fn isGawkOnlyBootstrapDependency(name: []const u8) bool {
    inline for (.{
        "gawk",
        "libmpfr6",
        "libreadline8t64",
        "readline-common",
    }) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

fn preferMawkOverGawkInFreshRootLock(
    native_backend: debz.NativePackageFamilyBackend,
    allocator: Allocator,
    request: debz.PackageFamilyRequest,
    lock_path: []const u8,
) !void {
    const io = native_backend.io;
    const lock_bytes = try readRegularFile(
        allocator,
        io,
        lock_path,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer allocator.free(lock_bytes);
    var lock = try debz.decodeExactClosureLockV3(
        allocator,
        lock_bytes,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer lock.deinit();

    var has_gawk_dependency = false;
    for (lock.lock.packages) |pkg| {
        if (std.mem.eql(u8, pkg.name, "mawk")) return;
        if (std.mem.eql(u8, pkg.name, "gawk") and pkg.retention == .dependency) {
            has_gawk_dependency = true;
        }
    }
    if (!has_gawk_dependency) return;

    const mawk_state = try allocator.print("{s}/mawk-bootstrap-state", .{request.state});
    defer allocator.free(mawk_state);
    const mawk_lock_path = try allocator.print("{s}/mawk-bootstrap-lock.json", .{request.state});
    defer allocator.free(mawk_lock_path);
    Dir.cwd().deleteTree(io, mawk_state) catch {};
    Dir.cwd().deleteFile(io, mawk_lock_path) catch {};
    try Dir.cwd().createDirPath(io, mawk_state);
    defer Dir.cwd().deleteTree(io, mawk_state) catch {};
    defer Dir.cwd().deleteFile(io, mawk_lock_path) catch {};

    var mawk_request = request;
    mawk_request.package = "mawk";
    mawk_request.state = mawk_state;
    mawk_request.lock_output = mawk_lock_path;
    var mawk_resolved = try native_backend.execute(allocator, mawk_request);
    defer mawk_resolved.deinit();
    if (!mawk_resolved.result.succeeded) return error.MawkBootstrapResolveFailed;

    const mawk_lock_bytes = try readRegularFile(
        allocator,
        io,
        mawk_lock_path,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer allocator.free(mawk_lock_bytes);
    var mawk_lock = try debz.decodeExactClosureLockV3(
        allocator,
        mawk_lock_bytes,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer mawk_lock.deinit();

    var mawk_pkg: ?debz.exact_lock_v3.Package = null;
    for (mawk_lock.lock.packages) |pkg| {
        if (std.mem.eql(u8, pkg.name, "mawk")) {
            var copy = pkg;
            copy.retention = .dependency;
            mawk_pkg = copy;
            break;
        }
    }
    const replacement_mawk = mawk_pkg orelse return error.MawkBootstrapPackageMissing;

    var new_packages: std.ArrayListUnmanaged(debz.exact_lock_v3.Package) = .empty;
    defer new_packages.deinit(allocator);
    for (lock.lock.packages) |pkg| {
        if (pkg.retention == .dependency and isGawkOnlyBootstrapDependency(pkg.name)) continue;
        try new_packages.append(allocator, pkg);
    }
    try new_packages.append(allocator, replacement_mawk);

    var new_repositories: std.ArrayListUnmanaged(debz.exact_lock_v3.Repository) = .empty;
    defer new_repositories.deinit(allocator);
    for ([_][]const debz.exact_lock_v3.Repository{
        lock.lock.repositories,
        mawk_lock.lock.repositories,
    }) |repo_slice| {
        for (repo_slice) |repo| {
            var already_added = false;
            for (new_repositories.items) |existing| {
                if (std.mem.eql(u8, &existing.id, &repo.id)) {
                    already_added = true;
                    break;
                }
            }
            if (already_added) continue;
            var referenced = false;
            for (new_packages.items) |pkg| switch (pkg.origin) {
                .authenticated_repository => |origin| {
                    if (std.mem.eql(u8, &origin.repository_id, &repo.id)) {
                        referenced = true;
                        break;
                    }
                },
                .local_artifact => {},
            };
            if (referenced) try new_repositories.append(allocator, repo);
        }
    }

    var rebuilt = try debz.createExactClosureLockV3(allocator, .{
        .target_architecture = lock.lock.target_architecture,
        .request_sha256 = lock.lock.request_sha256,
        .policy_sha256 = lock.lock.policy_sha256,
        .repositories = new_repositories.items,
        .local_artifacts = lock.lock.local_artifacts,
        .packages = new_packages.items,
        .verified_origins = true,
    });
    defer rebuilt.deinit();
    const canonical = try rebuilt.lock.canonicalJson(allocator);
    defer allocator.free(canonical);
    try writeRegularFile(io, lock_path, canonical);
}

fn nativeDebzEvidenceFailure(
    operation: debz.package_family_backend.Operation,
    changed: bool,
    message: []const u8,
) debz.PackageFamilyResult {
    var result = debzFamilyFailure(operation, .recovery, .native_evidence_unavailable, message, true);
    result.changed = changed;
    return result;
}

fn debzFamilyFailure(
    operation: debz.package_family_backend.Operation,
    status: debz.ProductExitStatus,
    id: debz.package_family_backend.ErrorId,
    message: []const u8,
    recoverable: bool,
) debz.PackageFamilyResult {
    return .{
        .operation = operation,
        .succeeded = false,
        .exit_status = status,
        .diagnostic = .{ .id = id, .message = message, .recoverable = recoverable },
    };
}

fn consistentNativeDebzEvidence(request: debz.ProductRequest, response: debz.ProductResult) bool {
    if (response.operation != request.operation) return false;
    if (response.native_completion) |completion| {
        if (!response.changed or completion.settlement != .cleared or
            (completion.outcome == .succeeded) != (response.exit_status == .success) or
            (completion.outcome == .failed and response.exit_status != .transaction))
            return false;
        if (request.operation != .recover and
            (completion.operation != request.operation or
                !std.mem.eql(u8, &completion.caller_request_sha256, &debz.production_backend.productRequestDigest(request)) or
                !std.mem.eql(u8, &completion.caller_policy_sha256, &debz.production_backend.planningPolicyDigest(.native, request.options))))
            return false;
    }
    if (request.operation == .plan)
        return !response.changed and response.native_install == null and response.native_completion == null;
    if (request.operation == .recover)
        return response.native_install == null and
            (response.exit_status != .success or response.changed == (response.native_completion != null));
    if (response.exit_status != .success) return response.native_install == null;
    if (request.operation == .upgrade or request.operation == .upgrade_all)
        return response.native_install == null and response.changed == (response.native_completion != null);
    const install = response.native_install orelse return false;
    if (!std.mem.eql(u8, &install.caller_request_sha256, &debz.production_backend.productRequestDigest(request)) or
        !std.mem.eql(u8, &install.caller_policy_sha256, &debz.production_backend.planningPolicyDigest(.native, request.options)) or
        response.changed != (install.receipt != null) or
        response.changed != (response.native_completion != null))
        return false;
    if (install.receipt) |receipt| {
        const completion = response.native_completion.?;
        return std.mem.eql(u8, &install.lock_sha256, &completion.lock_sha256) and
            std.mem.eql(u8, &receipt.transaction_digest_sha256, &completion.transaction_digest_sha256) and
            std.mem.eql(u8, &receipt.completion_digest_sha256, &completion.completion_digest_sha256) and
            std.mem.eql(u8, &receipt.program_sha256, &completion.program_sha256);
    }
    return true;
}

fn debzArchitectures(
    allocator: Allocator,
    architectures: []const Architecture,
) ![]const debz.package_family_backend.Architecture {
    const mapped = try allocator.alloc(debz.package_family_backend.Architecture, architectures.len);
    for (architectures, 0..) |architecture, index| mapped[index] = switch (architecture) {
        .amd64 => .amd64,
        .arm64 => .arm64,
    };
    return mapped;
}

fn debzOperation(operation: Operation) debz.package_family_backend.Operation {
    return switch (operation) {
        .resolve_lock => .resolve_lock,
        .create => .create,
        .customize => .customize,
        .update => .update,
        .remove => unreachable,
        .recover => .recover,
        .inspect => .inspect,
    };
}

fn compatible(capabilities: debz.NativePackageFamilyCapabilities) bool {
    return std.mem.eql(u8, capabilities.schema, debz_capability_schema) and
        capabilities.version == debz_schema_version and
        std.mem.eql(u8, capabilities.request_schema, debz_request_schema) and
        std.mem.eql(u8, capabilities.result_schema, debz_result_schema) and
        std.mem.eql(u8, capabilities.exact_lock_schema, debz_exact_lock_schema) and
        capabilities.provenance_schema != null and
        std.mem.eql(u8, capabilities.provenance_schema.?, debz_provenance_schema) and
        std.mem.eql(u8, capabilities.family, "debian") and
        capabilities.transaction_backend == .native and
        !capabilities.invokes_apt and
        !capabilities.invokes_dpkg and
        capabilities.recovery == .disposable_or_recoverable and
        contains(capabilities.operations, "resolve-lock") and
        contains(capabilities.operations, "create") and
        contains(capabilities.operations, "customize") and
        contains(capabilities.operations, "update") and
        contains(capabilities.operations, "recover") and
        contains(capabilities.operations, "inspect") and
        contains(capabilities.implementations, "ubuntu-26.04") and
        contains(capabilities.implementations, "debian") and
        contains(capabilities.architectures, "amd64") and
        contains(capabilities.architectures, "arm64");
}

fn contains(values: []const []const u8, expected: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, expected)) return true;
    return false;
}

fn valid(request: Request) bool {
    return invalidRequestMessage(request) == null;
}

fn invalidRequestMessage(request: Request) ?[]const u8 {
    if (!std.mem.eql(u8, request.schema, request_schema) or request.version != api_version)
        return "invalid package-family schema";
    if (!absolute(request.inputs.root_stage) or !absolute(request.inputs.published_root) or
        !absolute(request.inputs.cache_path) or !absolute(request.inputs.state_path))
        return "package-family paths must be normalized absolute paths";
    if (std.mem.eql(u8, request.inputs.root_stage, request.inputs.published_root))
        return "package-family staging and publication paths must differ";
    if (pathContains(request.inputs.root_stage, request.inputs.published_root) or
        pathContains(request.inputs.published_root, request.inputs.root_stage))
        return "package-family staging and publication paths must not contain each other";
    if (overlaps(request.inputs.root_stage, request.inputs.cache_path) or
        overlaps(request.inputs.root_stage, request.inputs.state_path))
        return "package-family staging must not overlap cache or state";
    if (request.family == .rpm) return if (validRpm(request)) null else "invalid rpm package-family request";
    if ((request.inputs.source_paths.len == 0 and request.inputs.config_paths.len == 0) or
        request.inputs.keyring_paths.len == 0)
        return "debian package-family sources and keyrings are required";
    for (request.inputs.source_paths) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "debian source paths must be absolute and outside staging";
    for (request.inputs.config_paths) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "debian config paths must be absolute and outside staging";
    for (request.inputs.keyring_paths) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "debian keyring paths must be absolute and outside staging";
    for (request.inputs.foreign_architectures) |architecture|
        if (architecture == request.inputs.architecture)
            return "foreign architecture must differ from target architecture";
    if ((request.operation == .resolve_lock or request.operation == .create or request.operation == .customize) and
        request.packages.len == 0)
        return "package-family operation requires a package";
    if ((request.operation == .recover or request.operation == .inspect) and request.packages.len != 0)
        return "package-family operation does not accept packages";
    if (request.operation == .resolve_lock) {
        if (request.inputs.lock_input_path != null or request.inputs.lock_output_path == null)
            return "resolve-lock requires only a lock output path";
    } else if (request.operation != .inspect and request.inputs.lock_input_path == null)
        return "package-family mutation requires a lock input path";
    if (request.inputs.lock_output_path != null and request.inputs.lock_input_path == null and
        request.operation != .resolve_lock)
        return "lock output requires a lock input outside resolve-lock";
    if (request.inputs.lock_input_path) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "lock input must be absolute and outside staging";
    if (request.inputs.lock_output_path) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "lock output must be absolute and outside staging";
    if (request.inputs.credential_reference) |path|
        if (!absolute(path) or overlaps(request.inputs.root_stage, path))
            return "credential reference must be absolute and outside staging";
    if (request.inputs.deadline_ms != null and request.inputs.deadline_ms.? == 0)
        return "package-family deadline must be nonzero";
    return null;
}

fn validRpm(request: Request) bool {
    const options = request.inputs.rpm orelse return false;
    if (request.distribution != .azure_linux or options.repositories.len == 0 or
        options.actions.len == 0 or options.distro.len == 0 or
        options.release_version.len == 0) return false;
    if (!absolute(request.inputs.cache_path) or !absolute(options.scratch_path) or
        !absolute(options.rpmdb_path)) return false;
    if (request.operation != .resolve_lock and request.inputs.lock_output_path == null) return false;
    if (overlaps(request.inputs.root_stage, request.inputs.cache_path) or
        overlaps(request.inputs.root_stage, options.scratch_path)) return false;
    for (options.repositories) |repository| {
        if (repository.id.len == 0) return false;
        if ((repository.local_snapshot == null) == (repository.base_urls.len == 0)) return false;
        if (repository.local_snapshot) |path| if (!absolute(path)) return false;
        for (repository.gpg_key_paths) |path| if (!absolute(path)) return false;
    }
    if (options.bundle_input_path) |path| if (!absolute(path)) return false;
    if (options.bundle_output_path) |path| if (!absolute(path)) return false;
    if (options.bundle_input_path != null and options.bundle_output_path != null) return false;
    if (request.inputs.lock_input_path) |path| if (!absolute(path)) return false;
    if (request.inputs.lock_output_path) |path| if (!absolute(path)) return false;
    return true;
}

fn mutates(operation: Operation) bool {
    return operation != .resolve_lock and operation != .inspect;
}

fn requiresProvenance(operation: Operation) bool {
    return operation == .create or operation == .customize or operation == .update or operation == .remove;
}

fn publishes(operation: Operation) bool {
    return operation == .create or operation == .customize or operation == .update or operation == .remove;
}

fn cleanup(io: Io, request: Request) void {
    if (mutates(request.operation)) Dir.cwd().deleteTree(io, request.inputs.root_stage) catch {};
}

fn absolute(path: []const u8) bool {
    if (path.len <= 1 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    return child.len > parent.len and std.mem.startsWith(u8, child, parent) and
        child[parent.len] == '/';
}

fn overlaps(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right) or pathContains(left, right) or pathContains(right, left);
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

fn writeRegularFile(io: Io, path: []const u8, bytes: []const u8) !void {
    var file = try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn verifyLock(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    architecture: Architecture,
    installed_baseline: InstalledBaselinePolicy,
) ![32]u8 {
    const bytes = try readRegularFile(allocator, io, path, debz.exact_lock_v3.maximum_document_bytes);
    defer allocator.free(bytes);
    var lock = try debz.decodeExactClosureLockV3(
        allocator,
        bytes,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer lock.deinit();
    const expected = switch (architecture) {
        .amd64 => "amd64",
        .arm64 => "arm64",
    };
    if (!std.mem.eql(u8, lock.lock.target_architecture, expected))
        return error.ArchitectureMismatch;
    if (installed_baseline == .require_locked) {
        var retained = false;
        for (lock.lock.packages) |package| {
            if (package.retention == .retained) {
                retained = true;
                break;
            }
        }
        if (!retained) return error.InstalledBaselineMissing;
    }
    return lock.lock.digest_sha256;
}

fn verifyProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    lock_digest: [32]u8,
) ![]u8 {
    const bytes = try readRegularFile(
        allocator,
        io,
        path,
        debz.native_provenance.maximum_document_bytes,
    );
    errdefer allocator.free(bytes);
    var provenance = try debz.native_provenance.decode(allocator, bytes);
    defer provenance.deinit();
    if (provenance.document.outcome != .succeeded) return error.InvalidProvenance;
    const expected = std.fmt.bytesToHex(lock_digest, .lower);
    if (!std.mem.eql(u8, &provenance.document.exact_lock_sha256, &expected))
        return error.InvalidProvenance;
    return bytes;
}

fn failed(
    id: DiagnosticId,
    message: []const u8,
    disposition: FailureDisposition,
    exit_status: ?u8,
) Result {
    return .{
        .succeeded = false,
        .published = false,
        .diagnostic = .{
            .id = id,
            .message = message,
            .disposition = disposition,
            .backend_exit_status = exit_status,
        },
    };
}

const FakeProduct = struct {
    io: Io,
    state_path: []const u8,
    lock_path: []const u8,
    seen_operation: ?debz.ProductOperation = null,
    seen_packages: usize = 0,
    fail_status: ?debz.ProductExitStatus = null,
    // When set, the failure summary is allocated with the caller's allocator,
    // faithfully reproducing the real debz backend whose describeExecutorFailure
    // heap-allocates the diagnostic message. Exercises the embedder's ownership
    // of that escaping message (regression for the production customize leak).
    heap_message: bool = false,

    fn interface(self: *FakeProduct) debz.ProductBackend {
        return .{ .context = self, .executeFn = executeProduct };
    }

    fn executeProduct(
        context: *anyopaque,
        allocator: Allocator,
        request: debz.ProductRequest,
    ) !debz.ProductResult {
        const self: *FakeProduct = @ptrCast(@alignCast(context));
        self.seen_operation = request.operation;
        self.seen_packages = request.packages.len;
        if (self.fail_status) |status| {
            const message = if (self.heap_message)
                try allocator.print(
                    "backend stage failed: FileNotFound opening credential=https://secret@example.invalid state lock",
                    .{},
                )
            else
                "credential=https://secret@example.invalid";
            return debz.product_api.failure(request.operation, status, .transaction_failed, message);
        }
        if (request.options.lock_output_path orelse request.options.lock_input_path) |path| {
            if (request.options.lock_output_path != null)
                try writeTestLock(self.io, path, request.options.architecture);
        }
        if (request.operation.mutates() and request.operation != .recover and request.options.lock_input_path != null) {
            const debz_dir = try std.testing.allocator.print("{s}/var/lib/debz", .{request.options.install_root});
            defer std.testing.allocator.free(debz_dir);
            try Dir.cwd().createDirPath(self.io, debz_dir);
            const provenance = try std.testing.allocator.print(
                "{s}/{s}",
                .{ request.options.install_root, debz.native_provenance.document_path },
            );
            defer std.testing.allocator.free(provenance);
            try writeTestProvenance(self.io, request.options.lock_input_path.?, provenance);
        }
        return .{
            .operation = request.operation,
            .exit_status = .success,
            .changed = request.operation.mutates(),
            .summary = "ok",
        };
    }
};

fn writeTestLock(io: Io, path: []const u8, architecture: []const u8) !void {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const repositories = [_]debz.exact_lock_v3.Repository{.{
        .id = repository_id,
        .snapshot_sha256 = snapshot,
        .release_sha256 = @splat(2),
        .index_identity = .{
            .digests = .{ .sha256 = @splat(3) },
            .primary = .sha256,
        },
        .signer_fingerprints = &.{@splat(4)},
    }};
    const packages = [_]debz.exact_lock_v3.Package{.{
        .name = "fixture",
        .version = "1",
        .architecture = architecture,
        .origin = .{
            .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            },
        },
        .archive_identity = .{
            .digests = .{ .sha256 = @splat(5), .sha512 = @splat(6) },
            .primary = .sha512,
        },
        .declared_size = 1,
        .retention = .requested,
        .dpkg_selection_hold = false,
    }};
    var lock = try debz.createExactClosureLockV3(std.testing.allocator, .{
        .target_architecture = architecture,
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = &repositories,
        .local_artifacts = &.{},
        .packages = &packages,
        .verified_origins = true,
    });
    defer lock.deinit();
    const bytes = try lock.lock.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var file = try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn writeTestProvenance(io: Io, lock_path: []const u8, path: []const u8) !void {
    const lock_bytes = try readRegularFile(
        std.testing.allocator,
        io,
        lock_path,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer std.testing.allocator.free(lock_bytes);
    var lock = try debz.decodeExactClosureLockV3(
        std.testing.allocator,
        lock_bytes,
        debz.exact_lock_v3.maximum_document_bytes,
    );
    defer lock.deinit();
    const evidence_root =
        "var/lib/debz/native-receipts-v1/1111111111111111111111111111111111111111111111111111111111111111";
    const evidence_files = [_]debz.native_provenance.EvidenceFile{
        .{
            .kind = .authorization,
            .path = evidence_root ++ "/authorization.json",
            .sha256 = @splat('1'),
            .document_sha256 = @splat('2'),
            .size = 1,
        },
        .{
            .kind = .program,
            .path = evidence_root ++ "/program.json",
            .sha256 = @splat('2'),
            .document_sha256 = @splat('3'),
            .size = 1,
        },
        .{
            .kind = .intent,
            .path = evidence_root ++ "/intent.json",
            .sha256 = @splat('3'),
            .document_sha256 = @splat('4'),
            .size = 1,
        },
        .{
            .kind = .progress,
            .path = evidence_root ++ "/progress.json",
            .sha256 = @splat('4'),
            .document_sha256 = @splat('5'),
            .size = 1,
        },
        .{
            .kind = .managed_state,
            .path = evidence_root ++ "/managed-state.json",
            .sha256 = @splat('5'),
            .document_sha256 = @splat('6'),
            .size = 1,
        },
        .{
            .kind = .trigger_events,
            .path = evidence_root ++ "/trigger-events.json",
            .sha256 = @splat('6'),
            .document_sha256 = @splat('7'),
            .size = 1,
        },
    };
    var document: debz.native_provenance.Document = .{
        .authority = .{
            .execution_request_schema = "https://debz.dev/schema/native-execution-request-v4",
            .execution_request_version = 4,
            .authorization_schema = "https://debz.dev/schema/native-transaction-authorization-v2",
            .authorization_version = 2,
            .program_schema = "https://debz.dev/schema/native-transaction-program-v2",
            .program_version = 2,
            .exact_lock_schema = "https://debz.dev/schema/exact-closure-lock-v3",
            .exact_lock_version = 3,
            .execution_intent_schema = "https://debz.dev/schema/native-execution-intent-v2",
            .execution_intent_version = 2,
            .progress_schema = "https://debz.dev/schema/native-execution-progress-v3",
            .progress_version = 3,
        },
        .attempt_id = @splat('1'),
        .install_root = "/srv/root",
        .root_identity_sha256 = debz.native_provenance.hexDigest(
            debz.transaction_recovery.rootIdentity("/srv/root"),
        ),
        .root_inode = 42,
        .operation = .{ .package_transaction = .install },
        .request_sha256 = @splat('3'),
        .policy_sha256 = @splat('4'),
        .authorization_sha256 = @splat('5'),
        .program_sha256 = @splat('6'),
        .exact_lock_sha256 = debz.native_provenance.hexDigest(lock.lock.digest_sha256),
        .artifact_evidence_sha256 = @splat('8'),
        .initial_database_generation_sha256 = @splat('9'),
        .execution_intent_sha256 = @splat('a'),
        .progress_head_sha256 = @splat('b'),
        .progress_record_count = 12,
        .script_outcomes_sha256 = @splat('c'),
        .trigger_evidence_sha256 = @splat('d'),
        .final_database_generation_sha256 = @splat('e'),
        .final_state_sha256 = @splat('f'),
        .recovered_phase_count = 1,
        .evidence_root = evidence_root,
        .evidence_files = &evidence_files,
        .evidence_files_sha256 = debz.native_provenance.evidenceDigest(&evidence_files),
        .final_state_kind = .package_database_closure_v1,
        .outcome = .succeeded,
        .detail = "recovered",
        .digest_sha256 = @splat('0'),
    };
    debz.native_provenance.seal(&document);
    const bytes = try document.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var file = try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn fixturePaths(allocator: Allocator, io: Io, suffix: []const u8) !struct {
    stage: []u8,
    output: []u8,
    state: []u8,
    lock: []u8,
} {
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    return .{
        .stage = try allocator.print("{s}/.test-package-{s}-stage", .{ cwd, suffix }),
        .output = try allocator.print("{s}/.test-package-{s}-root", .{ cwd, suffix }),
        .state = try allocator.print("{s}/.test-package-{s}-state", .{ cwd, suffix }),
        .lock = try allocator.print("{s}/.test-package-{s}.lock", .{ cwd, suffix }),
    };
}

test "installed baseline policy rejects action-only locks for both architectures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = try fixturePaths(allocator, io, "baseline-policy");
    defer allocator.free(paths.stage);
    defer allocator.free(paths.output);
    defer allocator.free(paths.state);
    defer allocator.free(paths.lock);
    defer Dir.cwd().deleteFile(io, paths.lock) catch {};

    for ([_]struct { spelling: []const u8, architecture: Architecture }{
        .{ .spelling = "amd64", .architecture = .amd64 },
        .{ .spelling = "arm64", .architecture = .arm64 },
    }) |case| {
        try writeTestLock(io, paths.lock, case.spelling);
        try std.testing.expectError(
            error.InstalledBaselineMissing,
            verifyLock(
                allocator,
                io,
                paths.lock,
                case.architecture,
                .require_locked,
            ),
        );
    }
}

test "embedded debz product executor resolves reviewed lock then publishes Ubuntu fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = try fixturePaths(allocator, io, "ubuntu");
    defer allocator.free(paths.stage);
    defer allocator.free(paths.output);
    defer allocator.free(paths.state);
    defer allocator.free(paths.lock);
    defer Dir.cwd().deleteTree(io, paths.stage) catch {};
    defer Dir.cwd().deleteTree(io, paths.output) catch {};
    defer Dir.cwd().deleteTree(io, paths.state) catch {};
    defer Dir.cwd().deleteFile(io, paths.lock) catch {};
    try Dir.cwd().createDir(io, paths.stage, .default_dir);
    try Dir.cwd().createDir(io, paths.state, .default_dir);

    var fake: FakeProduct = .{ .io = io, .state_path = paths.state, .lock_path = paths.lock };
    const backends: BackendSet = .{ .debian = .{ .product_executor = fake.interface() } };
    const common: Inputs = .{
        .root_stage = paths.stage,
        .published_root = paths.output,
        .architecture = .amd64,
        .foreign_architectures = &.{.arm64},
        .source_paths = &.{"/fixtures/ubuntu.sources"},
        .keyring_paths = &.{"/fixtures/ubuntu.gpg"},
        .cache_path = "/cache/debz",
        .state_path = paths.state,
        .lock_output_path = paths.lock,
        .cache_mode = .offline,
    };
    const resolved = try execute(allocator, io, backends, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .resolve_lock,
        .packages = &.{"ubuntu-minimal"},
        .inputs = common,
    });
    try std.testing.expect(resolved.succeeded);
    try std.testing.expectEqual(debz.ProductOperation.plan, fake.seen_operation.?);

    var locked = common;
    locked.lock_output_path = null;
    locked.lock_input_path = paths.lock;
    const created = try execute(allocator, io, backends, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .create,
        .packages = &.{"ubuntu-minimal"},
        .inputs = locked,
    });
    defer if (created.provenance_path) |path| allocator.free(path);
    try std.testing.expect(created.succeeded);
    try std.testing.expect(created.published);
    try std.testing.expectEqual(@as(usize, 1), fake.seen_packages);
    _ = try Dir.cwd().statFile(io, paths.output, .{});
    const published_debz_dir = try allocator.print("{s}/var/lib/debz", .{paths.output});
    defer allocator.free(published_debz_dir);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, published_debz_dir, .{}));
    const state_provenance = try allocator.print("{s}/transaction-result.json", .{paths.state});
    defer allocator.free(state_provenance);
    _ = try Dir.cwd().statFile(io, state_provenance, .{});
    try std.testing.expectEqualStrings(state_provenance, created.provenance_path.?);
}

test "multiple package names are rejected without invoking debz" {
    var fake: FakeProduct = .{
        .io = std.testing.io,
        .state_path = "/state/debz",
        .lock_path = "/state/debz.lock",
    };
    const result = try execute(std.testing.allocator, std.testing.io, .{
        .debian = .{ .product_executor = fake.interface() },
    }, .{
        .family = .debian,
        .distribution = .debian,
        .operation = .update,
        .packages = &.{ "one", "two" },
        .inputs = .{
            .root_stage = "/build/root-stage",
            .published_root = "/build/root",
            .architecture = .amd64,
            .source_paths = &.{"/inputs/debian.sources"},
            .keyring_paths = &.{"/inputs/debian.gpg"},
            .cache_path = "/cache/debz",
            .state_path = "/state/debz",
            .lock_input_path = "/state/debz.lock",
        },
    });
    try std.testing.expectEqual(DiagnosticId.unsupported_package_count, result.diagnostic.?.id);
    try std.testing.expect(fake.seen_operation == null);
}

test "immutable repository configs can supply all source documents" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = try fixturePaths(allocator, io, "config-only");
    defer allocator.free(paths.stage);
    defer allocator.free(paths.output);
    defer allocator.free(paths.state);
    defer allocator.free(paths.lock);
    defer Dir.cwd().deleteTree(io, paths.stage) catch {};
    defer Dir.cwd().deleteTree(io, paths.output) catch {};
    defer Dir.cwd().deleteTree(io, paths.state) catch {};
    defer Dir.cwd().deleteFile(io, paths.lock) catch {};
    try Dir.cwd().createDir(io, paths.stage, .default_dir);
    try Dir.cwd().createDir(io, paths.state, .default_dir);

    var fake: FakeProduct = .{ .io = io, .state_path = paths.state, .lock_path = paths.lock };
    const result = try execute(allocator, io, .{
        .debian = .{ .product_executor = fake.interface() },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .resolve_lock,
        .packages = &.{"linux-azure"},
        .inputs = .{
            .root_stage = paths.stage,
            .published_root = paths.output,
            .architecture = .amd64,
            .source_paths = &.{},
            .config_paths = &.{"/inputs/ubuntu-snapshot.json"},
            .keyring_paths = &.{"/inputs/ubuntu.gpg"},
            .cache_path = "/cache/debz",
            .state_path = paths.state,
            .lock_output_path = paths.lock,
        },
    });
    try std.testing.expect(result.succeeded);
    try std.testing.expectEqual(debz.ProductOperation.plan, fake.seen_operation.?);
}

test "capability mismatch is a typed boundary failure" {
    var capabilities = debz.nativePackageFamilyCapabilities();
    capabilities.version += 1;
    const result = try execute(std.testing.allocator, std.testing.io, .{
        .debian = .{ .capabilities = capabilities },
    }, .{
        .family = .debian,
        .distribution = .debian,
        .operation = .inspect,
        .inputs = .{
            .root_stage = "/build/root-stage",
            .published_root = "/build/root",
            .architecture = .amd64,
            .source_paths = &.{"/inputs/debian.sources"},
            .keyring_paths = &.{"/inputs/debian.gpg"},
            .cache_path = "/cache/debz",
            .state_path = "/state/debz",
        },
    });
    try std.testing.expectEqual(DiagnosticId.incompatible_backend, result.diagnostic.?.id);
}

test "backend diagnostics redact credentials and preserve recoverable stage" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = try fixturePaths(allocator, io, "failure");
    defer allocator.free(paths.stage);
    defer allocator.free(paths.output);
    defer allocator.free(paths.state);
    defer allocator.free(paths.lock);
    defer Dir.cwd().deleteTree(io, paths.stage) catch {};
    defer Dir.cwd().deleteTree(io, paths.output) catch {};
    defer Dir.cwd().deleteTree(io, paths.state) catch {};
    try Dir.cwd().createDir(io, paths.stage, .default_dir);
    try Dir.cwd().createDir(io, paths.state, .default_dir);
    var fake: FakeProduct = .{
        .io = io,
        .state_path = paths.state,
        .lock_path = paths.lock,
        .fail_status = .transaction,
    };
    const result = try execute(allocator, io, .{
        .debian = .{ .product_executor = fake.interface() },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .update,
        .inputs = .{
            .root_stage = paths.stage,
            .published_root = paths.output,
            .architecture = .arm64,
            .source_paths = &.{"/inputs/ubuntu.sources"},
            .keyring_paths = &.{"/inputs/ubuntu.gpg"},
            .cache_path = "/cache/debz",
            .state_path = paths.state,
            .lock_input_path = paths.lock,
            .credential_reference = "/run/credentials/debz",
        },
    });
    try std.testing.expectEqual(FailureDisposition.recoverable, result.diagnostic.?.disposition);
    try std.testing.expect(std.mem.indexOf(u8, result.diagnostic.?.message, "secret") == null);
    _ = try Dir.cwd().statFile(io, paths.stage, .{});
}

test "customize failure reports exit 7 and frees the escaping debz diagnostic for both architectures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    // Reproduces the production aarch64 customize failure (backend_failed / exit 7)
    // for both request shapes. The fake backend heap-allocates its diagnostic
    // summary exactly as the real debz backend does; running on the leak-checking
    // testing allocator asserts the embedder owns and frees that escaping message.
    for ([_]Architecture{ .arm64, .amd64 }) |architecture| {
        const paths = try fixturePaths(allocator, io, @tagName(architecture));
        defer allocator.free(paths.stage);
        defer allocator.free(paths.output);
        defer allocator.free(paths.state);
        defer allocator.free(paths.lock);
        defer Dir.cwd().deleteTree(io, paths.stage) catch {};
        defer Dir.cwd().deleteTree(io, paths.output) catch {};
        defer Dir.cwd().deleteTree(io, paths.state) catch {};
        try Dir.cwd().createDir(io, paths.stage, .default_dir);
        try Dir.cwd().createDir(io, paths.state, .default_dir);
        var fake: FakeProduct = .{
            .io = io,
            .state_path = paths.state,
            .lock_path = paths.lock,
            .fail_status = .transaction,
            .heap_message = true,
        };
        const result = try execute(allocator, io, .{
            .debian = .{ .product_executor = fake.interface() },
        }, .{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = .customize,
            .packages = &.{"ubuntu-minimal"},
            .inputs = .{
                .root_stage = paths.stage,
                .published_root = paths.output,
                .architecture = architecture,
                .source_paths = &.{"/inputs/ubuntu.sources"},
                .keyring_paths = &.{"/inputs/ubuntu.gpg"},
                .cache_path = "/cache/debz",
                .state_path = paths.state,
                .lock_input_path = paths.lock,
                .credential_reference = "/run/credentials/debz",
            },
        });
        try std.testing.expect(!result.succeeded);
        try std.testing.expect(!result.published);
        try std.testing.expectEqual(DiagnosticId.backend_failed, result.diagnostic.?.id);
        try std.testing.expectEqual(@as(?u8, 7), result.diagnostic.?.backend_exit_status);
        try std.testing.expectEqual(FailureDisposition.recoverable, result.diagnostic.?.disposition);
        try std.testing.expect(std.mem.indexOf(u8, result.diagnostic.?.message, "secret") == null);
        // A recoverable customize failure preserves the staged root for retry.
        _ = try Dir.cwd().statFile(io, paths.stage, .{});
    }
}

test "arm64 resolve then customize completes the exact-lock handoff without leaking" {
    // Deterministic, offline arm64 equivalent of the production resolve->customize
    // transition that failed at customize time (issue #455). A full arm64 image
    // build is not reproducible on an x86_64 host (no aarch64 systemd-boot stub),
    // so this drives the exact package-family boundary the builder drives, with
    // arm64 request/lock/cache/root/state paths, across BOTH operations. The real
    // debz lock-root provisioning (creating the absent var/lib/debz) is proven
    // end to end by debz's production_backend_customize_test.zig; here the aim is
    // miz's orchestration: resolve emits the exact lock, customize consumes that
    // same lock, publication and provenance succeed, and nothing leaks.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = try fixturePaths(allocator, io, "arm64-handoff");
    defer allocator.free(paths.stage);
    defer allocator.free(paths.output);
    defer allocator.free(paths.state);
    defer allocator.free(paths.lock);
    defer Dir.cwd().deleteTree(io, paths.stage) catch {};
    defer Dir.cwd().deleteTree(io, paths.output) catch {};
    defer Dir.cwd().deleteTree(io, paths.state) catch {};
    defer Dir.cwd().deleteFile(io, paths.lock) catch {};

    // Stage the exact shape of an authenticated official Ubuntu arm64 root: it
    // ships var/lib/dpkg but never var/lib/debz. That absence is what made the
    // production transaction lock open into a missing parent and surface a bare
    // FileNotFound the first time customize ran after resolve.
    try Dir.cwd().createDir(io, paths.stage, .default_dir);
    const dpkg_dir = try allocator.print("{s}/var/lib/dpkg", .{paths.stage});
    defer allocator.free(dpkg_dir);
    try Dir.cwd().createDirPath(io, dpkg_dir);
    try Dir.cwd().createDir(io, paths.state, .default_dir);
    const debz_dir = try allocator.print("{s}/var/lib/debz", .{paths.stage});
    defer allocator.free(debz_dir);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, debz_dir, .{}));

    const config = [_][]const u8{"/inputs/ubuntu-snapshot.json"};
    const keyring = [_][]const u8{"/inputs/ubuntu.gpg"};
    const cache = "/cache/debz-arm64";

    // --- resolve: the exact lock is written for the arm64 target ---
    var resolver: FakeProduct = .{ .io = io, .state_path = paths.state, .lock_path = paths.lock };
    const resolved = try execute(allocator, io, .{
        .debian = .{ .product_executor = resolver.interface() },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .resolve_lock,
        .packages = &.{"linux-azure"},
        .inputs = .{
            .root_stage = paths.stage,
            .published_root = paths.output,
            .architecture = .arm64,
            .source_paths = &.{},
            .config_paths = &config,
            .keyring_paths = &keyring,
            .cache_path = cache,
            .state_path = paths.state,
            .lock_output_path = paths.lock,
        },
    });
    try std.testing.expect(resolved.succeeded);
    try std.testing.expectEqual(debz.ProductOperation.plan, resolver.seen_operation.?);
    try std.testing.expect(resolved.lock_path != null);
    try std.testing.expectEqualStrings(paths.lock, resolved.lock_path.?);

    // The emitted lock targets arm64, never the foreign architecture.
    const lock_after_resolve = try Dir.cwd().readFileAlloc(io, paths.lock, allocator, .limited(1 << 20));
    defer allocator.free(lock_after_resolve);
    try std.testing.expect(std.mem.indexOf(u8, lock_after_resolve, "arm64") != null);
    try std.testing.expect(std.mem.indexOf(u8, lock_after_resolve, "amd64") == null);

    // --- customize: the same lock is consumed, the root is published ---
    var customizer: FakeProduct = .{ .io = io, .state_path = paths.state, .lock_path = paths.lock };
    const customized = try execute(allocator, io, .{
        .debian = .{ .product_executor = customizer.interface() },
    }, .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .customize,
        .packages = &.{"linux-azure"},
        .inputs = .{
            .root_stage = paths.stage,
            .published_root = paths.output,
            .architecture = .arm64,
            .source_paths = &.{},
            .config_paths = &config,
            .keyring_paths = &keyring,
            .cache_path = cache,
            .state_path = paths.state,
            .lock_input_path = paths.lock,
        },
    });
    try std.testing.expect(customized.succeeded);
    try std.testing.expect(customized.published);
    try std.testing.expect(customized.provenance_path != null);
    // provenance_path must be owned by the caller's allocator (freed here); the
    // production customize leak was exactly an unfreed escaping backend string.
    defer allocator.free(customized.provenance_path.?);
    const expected_provenance = try allocator.print("{s}/transaction-result.json", .{paths.state});
    defer allocator.free(expected_provenance);
    try std.testing.expectEqualStrings(expected_provenance, customized.provenance_path.?);

    // Exact-lock semantics: customize consumed the resolve output verbatim.
    const lock_after_customize = try Dir.cwd().readFileAlloc(io, paths.lock, allocator, .limited(1 << 20));
    defer allocator.free(lock_after_customize);
    try std.testing.expectEqualSlices(u8, lock_after_resolve, lock_after_customize);
}

test "pathsOverlap matches containment in either direction but not siblings" {
    try std.testing.expect(pathsOverlap("/work", "/work"));
    try std.testing.expect(pathsOverlap("/work", "/work/root-stage"));
    try std.testing.expect(pathsOverlap("/work/root-stage", "/work"));
    try std.testing.expect(!pathsOverlap("/work/root-stage", "/work/keyring.gpg"));
    try std.testing.expect(!pathsOverlap("/work/root", "/work/root-stage"));
}

test "requestViolation reuses boundary policy and forbids publication overlap" {
    const separated: Inputs = .{
        .root_stage = "/work/root-stage",
        .published_root = "/work/root",
        .architecture = .amd64,
        .source_paths = &.{},
        .config_paths = &.{"/work/ubuntu-snapshot.json"},
        .keyring_paths = &.{"/work/ubuntu-archive-keyring.gpg"},
        .cache_path = "/work/debz/cache",
        .state_path = "/work/debz/state",
        .lock_output_path = "/work/debz/exact-lock.json",
    };
    const well_formed: Request = .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .resolve_lock,
        .packages = &.{"linux-azure"},
        .inputs = separated,
    };
    try std.testing.expect(requestViolation(well_formed) == null);

    // A keyring resolved from inside the resolve root_stage reproduces the exact
    // boundary rejection that broke the protected aarch64 builder.
    var keyring_in_stage = separated;
    keyring_in_stage.keyring_paths = &.{"/work/root-stage/usr/share/keyrings/ubuntu-archive-keyring.gpg"};
    try std.testing.expectEqualStrings(
        "debian keyring paths must be absolute and outside staging",
        requestViolation(.{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = .resolve_lock,
            .packages = &.{"linux-azure"},
            .inputs = keyring_in_stage,
        }).?,
    );

    // A keyring living under the publication root would be captured or mutated
    // by the published guest, so requestViolation rejects it even though the
    // looser boundary check tolerates it.
    var keyring_in_published = separated;
    keyring_in_published.keyring_paths = &.{"/work/root/usr/share/keyrings/ubuntu-archive-keyring.gpg"};
    try std.testing.expectEqualStrings(
        "debian keyring paths must be outside publication",
        requestViolation(.{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = .resolve_lock,
            .packages = &.{"linux-azure"},
            .inputs = keyring_in_published,
        }).?,
    );

    var cache_in_published = separated;
    cache_in_published.cache_path = "/work/root/var/cache/debz";
    try std.testing.expectEqualStrings(
        "package-family publication must not overlap cache or state",
        requestViolation(.{
            .family = .debian,
            .distribution = .ubuntu_26_04,
            .operation = .resolve_lock,
            .packages = &.{"linux-azure"},
            .inputs = cache_in_published,
        }).?,
    );
}
