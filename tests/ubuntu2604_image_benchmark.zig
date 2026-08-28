//! Unit tests for the Ubuntu 26.04 bare-metal image benchmark.
//!
//! Port of `tests/ubuntu2604_image_benchmark_test.py`. Every test here is a
//! negative or mutation test of a contract that makes a measurement
//! trustworthy: the fixed profile and offline inputs of the builder command,
//! the content-addressed cache and exact locks, the timing schema, the raw
//! output, the median, the semantic correctness comparison and its
//! non-leaking diagnostics, and the bounded cleanup. The subcommands the
//! benchmark workflow drives are covered here too, because they replaced
//! inline workflow code that nothing else tests.

const std = @import("std");
const benchmark = @import("benchmark");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;

/// A private, absolute temporary tree plus the arena and failure context the
/// benchmark API takes. The paths are absolute because the code under test
/// resolves and re-resolves them.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    arena_state: *std.heap.ArenaAllocator,
    root: []const u8,
    context: benchmark.Context,
    io: Io,

    fn create() !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        // The arena lives behind a stable address: the fixture is returned by
        // value, and an `Allocator` captured from it must stay valid.
        const arena_state = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(arena_state);
        arena_state.* = .init(std.testing.allocator);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();
        const relative = try std.fmt.allocPrint(
            arena,
            ".zig-cache/tmp/{s}",
            .{tmp.sub_path},
        );
        const root = try Dir.cwd().realPathFileAlloc(
            std.testing.io,
            relative,
            arena,
        );
        return .{
            .tmp = tmp,
            .arena_state = arena_state,
            .root = root,
            .context = .init(arena),
            .io = std.testing.io,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena_state.deinit();
        std.testing.allocator.destroy(self.arena_state);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn allocator(self: *Fixture) Allocator {
        return self.arena_state.allocator();
    }

    fn path(self: *Fixture, parts: []const []const u8) ![]const u8 {
        var joined: std.ArrayList([]const u8) = .empty;
        defer joined.deinit(self.allocator());
        try joined.append(self.allocator(), self.root);
        try joined.appendSlice(self.allocator(), parts);
        return std.fs.path.join(self.allocator(), joined.items);
    }

    fn mkdir(self: *Fixture, parts: []const []const u8) ![]const u8 {
        const target = try self.path(parts);
        try Dir.cwd().createDirPath(self.io, target);
        return target;
    }

    fn write(self: *Fixture, parts: []const []const u8, data: []const u8) ![]const u8 {
        const target = try self.path(parts);
        if (std.fs.path.dirname(target)) |parent| {
            try Dir.cwd().createDirPath(self.io, parent);
        }
        try Dir.cwd().writeFile(self.io, .{ .sub_path = target, .data = data });
        return target;
    }

    fn read(self: *Fixture, target: []const u8) ![]u8 {
        return Dir.cwd().readFileAlloc(self.io, target, self.allocator(), .unlimited);
    }

    fn exists(self: *Fixture, target: []const u8) bool {
        _ = Dir.cwd().statFile(self.io, target, .{ .follow_symlinks = false }) catch
            return false;
        return true;
    }

    fn parse(self: *Fixture, text: []const u8) !Value {
        return std.json.parseFromSliceLeaky(Value, self.allocator(), text, .{});
    }

    /// The message the last failure recorded, for tests that assert on the
    /// operator-facing text rather than only on the failure itself.
    fn message(self: *Fixture) []const u8 {
        return self.context.message();
    }
};

fn expectFailure(result: anytype) !void {
    try std.testing.expectError(error.Benchmark, result);
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print(
            "\nexpected to find:\n  {s}\nin:\n  {s}\n",
            .{ needle, haystack },
        );
        return error.TestExpectedContains;
    }
}

fn expectExcludes(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print(
            "\nexpected not to find:\n  {s}\nin:\n  {s}\n",
            .{ needle, haystack },
        );
        return error.TestExpectedExcludes;
    }
}

const digest_a = "a" ** 64;

fn hexDigest(allocator: Allocator, bytes: []const u8) ![]const u8 {
    var raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw, .{});
    return allocator.dupe(u8, &std.fmt.bytesToHex(raw, .lower));
}

/// The option set every `run` test starts from, with each named input present
/// on disk so path resolution behaves as it does in production.
fn baseArguments(fixture: *Fixture) ![][]const u8 {
    const allocator = fixture.allocator();
    var names: std.ArrayList([]const u8) = .empty;
    const files = [_][]const u8{
        "source",
        "sums",
        "signature",
        "manifest",
        "authorized-key",
        "stub",
        "certificate",
        "signing-key",
        "zig",
    };
    for (files) |name| {
        try names.append(allocator, try fixture.write(&.{name}, name));
    }
    const cache = try fixture.mkdir(&.{"cache"});
    const debz_inputs = try fixture.mkdir(&.{"debz-inputs"});
    const locks = try fixture.mkdir(&.{"locks"});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(allocator, &.{
        "--output-root",                try fixture.path(&.{"output"}),
        "--source",                     names.items[0],
        "--sha256sums",                 names.items[1],
        "--sha256sums-signature",       names.items[2],
        "--manifest",                   names.items[3],
        "--debz-cache",                 cache,
        "--debz-input-dir",             debz_inputs,
        "--debz-lock-dir",              locks,
        "--authorized-key",             names.items[4],
        "--uki-stub",                   names.items[5],
        "--signing-certificate",        names.items[6],
        "--signing-certificate-sha256", digest_a,
        "--signing-key",                names.items[7],
        "--zig",                        names.items[8],
        "--zig-global-cache",           try fixture.path(&.{"zig-global"}),
    });
    return argv.toOwnedSlice(allocator);
}

const CacheFixture = struct {
    cache: []const u8,
    package_digest: []const u8,
    metadata_digest: []const u8,
};

/// A warm cache holding one metadata object, one package object, and either a
/// single arbitrary manifest or the exact manifest set `input_dir` requires.
fn makeCache(fixture: *Fixture, input_dir: ?[]const u8) !CacheFixture {
    const allocator = fixture.allocator();
    const cache = try fixture.path(&.{"cache-fixture"});
    const metadata = try fixture.mkdir(&.{ "cache-fixture", "metadata-v1", "objects" });
    const manifests = try fixture.mkdir(&.{ "cache-fixture", "metadata-v1", "manifests" });
    const packages = try fixture.mkdir(&.{ "cache-fixture", "packages-v1", "objects" });
    const metadata_bytes = "metadata";
    const metadata_digest = try hexDigest(allocator, metadata_bytes);
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = try std.fs.path.join(allocator, &.{ metadata, metadata_digest }),
        .data = metadata_bytes,
    });
    const package_bytes = "package";
    const package_digest = try hexDigest(allocator, package_bytes);
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = try std.fs.path.join(allocator, &.{ packages, package_digest }),
        .data = package_bytes,
    });

    const Requirement = struct { repository: []const u8, snapshot: []const u8, filename: []const u8 };
    var requirements: std.ArrayList(Requirement) = .empty;
    if (input_dir) |directory| {
        for (try benchmark.benchmarkCacheRequirements(
            allocator,
            fixture.io,
            directory,
        )) |requirement| {
            try requirements.append(allocator, .{
                .repository = requirement.repository,
                .snapshot = requirement.snapshot,
                .filename = requirement.filename,
            });
        }
    } else {
        const filename = benchmark.debzManifestName(digest_a, "fixture");
        try requirements.append(allocator, .{
            .repository = digest_a,
            .snapshot = "fixture",
            .filename = try allocator.dupe(u8, &filename),
        });
    }
    for (requirements.items) |requirement| {
        const body = try std.fmt.allocPrint(allocator,
            \\debz-metadata-manifest-v1
            \\repository={s}
            \\snapshot={s}
            \\digest={s}
            \\size={d}
            \\verification=trusted_snapshot
            \\verified-at=0
            \\verifier-input=-
            \\
        , .{
            requirement.repository,
            requirement.snapshot,
            metadata_digest,
            metadata_bytes.len,
        });
        try Dir.cwd().writeFile(fixture.io, .{
            .sub_path = try std.fs.path.join(
                allocator,
                &.{ manifests, requirement.filename },
            ),
            .data = body,
        });
    }
    return .{
        .cache = cache,
        .package_digest = package_digest,
        .metadata_digest = metadata_digest,
    };
}

fn makeLocks(fixture: *Fixture, package_digest: []const u8) ![]const u8 {
    const allocator = fixture.allocator();
    const locks = try fixture.mkdir(&.{"lock-fixture"});
    for (benchmark.package_roots, 0..) |package, index| {
        const digest = try allocator.alloc(u8, 64);
        @memset(digest, std.fmt.digitToChar(@intCast(index + 1), .lower));
        const document = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/exact-closure-lock-v1",
            \\ "version": 1,
            \\ "target_architecture": "arm64",
            \\ "digest_sha256": "{s}",
            \\ "packages": [{{"name": "{s}", "version": "1",
            \\               "architecture": "arm64", "sha256": "{s}"}}]}}
        , .{ digest, package, package_digest });
        const filename = try benchmark.lockFilename(allocator, package);
        try Dir.cwd().writeFile(fixture.io, .{
            .sub_path = try std.fs.path.join(allocator, &.{ locks, filename }),
            .data = document,
        });
    }
    return locks;
}

/// A complete, successful timing document, optionally with the raw
/// materialization phase recorded as skipped instead of run.
fn timingDocument(allocator: Allocator, raw_outcome: []const u8) ![]u8 {
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(allocator,
        \\{"schema": 1, "type": "miz-ubuntu2604-image-phase-timing",
        \\ "clock": "monotonic", "duration_unit": "nanoseconds",
        \\ "status": "success", "failed_phase": null, "failed_item": null,
        \\ "error_name": null, "phases": [
    );
    var elapsed: i64 = 1;
    for (benchmark.phase_order, 0..) |key, index| {
        const separator = std.mem.indexOfScalar(u8, key, ':');
        const name = if (separator) |at| key[0..at] else key;
        const item = if (separator) |at| key[at + 1 ..] else null;
        const outcome = if (std.mem.eql(u8, name, "raw_image_materialization"))
            raw_outcome
        else
            "success";
        const rendered = if (item) |present| try std.fmt.allocPrint(
            allocator,
            "{s}{{\"name\": \"{s}\", \"item\": \"{s}\", \"elapsed_ns\": {d}," ++
                " \"outcome\": \"{s}\", \"error_name\": null}}",
            .{ if (index == 0) "" else ", ", name, present, elapsed, outcome },
        ) else try std.fmt.allocPrint(
            allocator,
            "{s}{{\"name\": \"{s}\", \"item\": null, \"elapsed_ns\": {d}," ++
                " \"outcome\": \"{s}\", \"error_name\": null}}",
            .{ if (index == 0) "" else ", ", name, elapsed, outcome },
        );
        try text.appendSlice(allocator, rendered);
        elapsed += 1;
    }
    try text.appendSlice(allocator, "]}");
    return text.toOwnedSlice(allocator);
}

test "argument validation requires the exact signing shape" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const arguments = try baseArguments(&fixture);

    const parsed = try benchmark.parseArgs(allocator, fixture.io, arguments);
    try std.testing.expectEqualStrings(digest_a, parsed.signing_certificate_sha256);

    var with_command_argument: std.ArrayList([]const u8) = .empty;
    try with_command_argument.appendSlice(allocator, arguments);
    try with_command_argument.appendSlice(allocator, &.{ "--sign-command-arg", "sign" });
    try std.testing.expectError(error.Usage, benchmark.parseArgs(
        allocator,
        fixture.io,
        with_command_argument.items,
    ));

    var invalid: std.ArrayList([]const u8) = .empty;
    try invalid.appendSlice(allocator, arguments);
    for (invalid.items) |*argument| {
        if (std.mem.eql(u8, argument.*, digest_a)) argument.* = "not-a-digest";
    }
    try std.testing.expectError(error.Usage, benchmark.parseArgs(
        allocator,
        fixture.io,
        invalid.items,
    ));
}

test "an external signer must be absolute and cannot be combined with a key" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const arguments = try baseArguments(&fixture);

    var relative: std.ArrayList([]const u8) = .empty;
    try relative.appendSlice(allocator, arguments);
    for (relative.items, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, "--signing-key")) {
            relative.items[index] = "--sign-command";
            relative.items[index + 1] = "relative/signer";
        }
    }
    try std.testing.expectError(error.Usage, benchmark.parseArgs(
        allocator,
        fixture.io,
        relative.items,
    ));

    var both: std.ArrayList([]const u8) = .empty;
    try both.appendSlice(allocator, arguments);
    try both.appendSlice(allocator, &.{ "--sign-command", "/absolute/signer" });
    try std.testing.expectError(error.Usage, benchmark.parseArgs(
        allocator,
        fixture.io,
        both.items,
    ));

    var neither: std.ArrayList([]const u8) = .empty;
    for (arguments, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, "--signing-key")) continue;
        if (index > 0 and std.mem.eql(u8, arguments[index - 1], "--signing-key")) continue;
        try neither.append(allocator, argument);
    }
    try std.testing.expectError(error.Usage, benchmark.parseArgs(
        allocator,
        fixture.io,
        neither.items,
    ));
}

test "the benchmark command fixes the profile and its offline inputs" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const args = try benchmark.parseArgs(
        allocator,
        fixture.io,
        try baseArguments(&fixture),
    );
    const image = try fixture.path(&.{ "artifact", benchmark.asset_name });
    const command = try benchmark.benchmarkCommand(
        allocator,
        args,
        try fixture.path(&.{"work"}),
        try fixture.path(&.{"provenance"}),
        image,
        try fixture.path(&.{"timing.json"}),
    );

    const required = [_][]const u8{
        "-Doptimize=ReleaseSafe",
        "-Dubuntu2604-arch=aarch64",
        "-Dubuntu2604-flavor=baremetal",
        "--debz-lock-dir",
        "--debz-input-dir",
        "--offline",
    };
    for (required) |flag| {
        var found = false;
        for (command) |argument| {
            if (std.mem.eql(u8, argument, flag)) found = true;
        }
        if (!found) {
            std.debug.print("\nmissing builder argument: {s}\n", .{flag});
            return error.TestExpectedArgument;
        }
    }

    var raw_index: ?usize = null;
    for (command, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, "--raw-output")) raw_index = index;
    }
    try std.testing.expectEqualStrings(
        try fixture.path(&.{ "artifact", benchmark.raw_asset_name }),
        command[raw_index.? + 1],
    );
}

test "the run directory must be new" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const output = try fixture.path(&.{"new-output"});
    try std.testing.expectEqualStrings(output, try benchmark.prepareSessionDir(
        fixture.allocator(),
        fixture.io,
        output,
        &fixture.context,
    ));
    try expectFailure(benchmark.prepareSessionDir(
        fixture.allocator(),
        fixture.io,
        output,
        &fixture.context,
    ));
}

const RunLayout = struct {
    run: []const u8,
    work: []const u8,
    image: []const u8,
    raw_output: []const u8,
};

fn makeRunLayout(fixture: *Fixture) !RunLayout {
    const run = try fixture.mkdir(&.{"run"});
    _ = try fixture.mkdir(&.{ "run", "artifact" });
    const work = try fixture.mkdir(&.{ "run", "work" });
    const image = try fixture.write(&.{ "run", "artifact", benchmark.asset_name }, "image");
    const raw_output = try fixture.write(
        &.{ "run", "artifact", benchmark.raw_asset_name },
        "raw",
    );
    return .{ .run = run, .work = work, .image = image, .raw_output = raw_output };
}

test "cleanup rejects paths outside the exact run layout" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const layout = try makeRunLayout(&fixture);
    const outside = try fixture.mkdir(&.{"outside"});

    try expectFailure(benchmark.cleanupDecisions(
        fixture.allocator(),
        fixture.io,
        layout.run,
        layout.image,
        layout.raw_output,
        outside,
        false,
        &fixture.context,
    ));

    const outside_raw = try fixture.write(
        &.{ "outside", benchmark.raw_asset_name },
        "raw",
    );
    try expectFailure(benchmark.cleanupDecisions(
        fixture.allocator(),
        fixture.io,
        layout.run,
        layout.image,
        outside_raw,
        layout.work,
        false,
        &fixture.context,
    ));
}

test "cleanup removes only the validated large targets" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const layout = try makeRunLayout(&fixture);
    const removed = try benchmark.cleanupRun(
        fixture.allocator(),
        fixture.io,
        layout.run,
        layout.image,
        layout.raw_output,
        layout.work,
        false,
        &fixture.context,
    );
    const expected = [_][]const u8{
        "artifact/" ++ benchmark.asset_name,
        "artifact/" ++ benchmark.raw_asset_name,
        "work",
    };
    try std.testing.expectEqual(expected.len, removed.len);
    for (expected, removed) |want, got| try std.testing.expectEqualStrings(want, got);
    try std.testing.expect(!fixture.exists(layout.image));
    try std.testing.expect(!fixture.exists(layout.raw_output));
    try std.testing.expect(!fixture.exists(layout.work));
}

test "keeping images still discards only the work directory" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const layout = try makeRunLayout(&fixture);
    const removed = try benchmark.cleanupRun(
        fixture.allocator(),
        fixture.io,
        layout.run,
        layout.image,
        layout.raw_output,
        layout.work,
        true,
        &fixture.context,
    );
    try std.testing.expectEqual(@as(usize, 1), removed.len);
    try std.testing.expectEqualStrings("work", removed[0]);
    try std.testing.expect(fixture.exists(layout.image));
    try std.testing.expect(fixture.exists(layout.raw_output));
}

test "the warm cache verifies its content-addressed objects" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const cache = try makeCache(&fixture, null);
    var inventory = try benchmark.verifyWarmCache(
        fixture.allocator(),
        fixture.io,
        cache.cache,
        &fixture.context,
    );
    try std.testing.expectEqual(@as(usize, 1), inventory.package_objects);
    try std.testing.expect(inventory.hasPackageObject(cache.package_digest));

    _ = try fixture.write(
        &.{ "cache-fixture", "packages-v1", "objects", cache.package_digest },
        "corrupt",
    );
    try expectFailure(benchmark.verifyWarmCache(
        fixture.allocator(),
        fixture.io,
        cache.cache,
        &fixture.context,
    ));
}

test "cache manifests bind the stable signed-by path" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const stable = try fixture.mkdir(&.{"stable-inputs"});
    const cache = try makeCache(&fixture, stable);
    const inventory = try benchmark.verifyBenchmarkCache(
        allocator,
        fixture.io,
        cache.cache,
        stable,
        &fixture.context,
    );
    try std.testing.expectEqual(@as(usize, 25), inventory.metadata_manifests);

    // A per-run work directory is a different Signed-By path, so it requires a
    // disjoint manifest set: the cache identity is not accidentally stable.
    const measured = try fixture.mkdir(&.{ "run-warmup", "work" });
    const stable_requirements = try benchmark.benchmarkCacheRequirements(
        allocator,
        fixture.io,
        stable,
    );
    const measured_requirements = try benchmark.benchmarkCacheRequirements(
        allocator,
        fixture.io,
        measured,
    );
    for (stable_requirements) |left| {
        for (measured_requirements) |right| {
            try std.testing.expect(!std.mem.eql(u8, left.filename, right.filename));
        }
    }
    try expectFailure(benchmark.verifyBenchmarkCache(
        allocator,
        fixture.io,
        cache.cache,
        measured,
        &fixture.context,
    ));
    try expectContains(fixture.message(), "missing metadata manifest");
    try expectContains(fixture.message(), "for phase repository-refresh");
    try expectContains(fixture.message(), "identity binds Signed-By");
}

test "a cache manifest reports its missing metadata object" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const cache = try makeCache(&fixture, null);
    const filename = benchmark.debzManifestName(digest_a, "fixture");
    const manifest = try fixture.path(
        &.{ "cache-fixture", "metadata-v1", "manifests", &filename },
    );
    const contents = try fixture.read(manifest);
    const replaced = try std.mem.replaceOwned(
        u8,
        fixture.allocator(),
        contents,
        cache.metadata_digest,
        "f" ** 64,
    );
    try Dir.cwd().writeFile(fixture.io, .{ .sub_path = manifest, .data = replaced });
    try expectFailure(benchmark.verifyWarmCache(
        fixture.allocator(),
        fixture.io,
        cache.cache,
        &fixture.context,
    ));
    try expectContains(fixture.message(), "references missing object");
}

test "a manifest refresh does not change the CAS object inventory" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const stable = try fixture.mkdir(&.{"stable-inputs"});
    const cache = try makeCache(&fixture, stable);
    const before = try benchmark.verifyBenchmarkCache(
        allocator,
        fixture.io,
        cache.cache,
        stable,
        &fixture.context,
    );
    const requirements = try benchmark.benchmarkCacheRequirements(
        allocator,
        fixture.io,
        stable,
    );
    const manifest = try fixture.path(&.{
        "cache-fixture",
        "metadata-v1",
        "manifests",
        requirements[0].filename,
    });
    const contents = try fixture.read(manifest);
    const refreshed = try std.mem.replaceOwned(
        u8,
        allocator,
        contents,
        "verified-at=0",
        "verified-at=1",
    );
    try Dir.cwd().writeFile(fixture.io, .{ .sub_path = manifest, .data = refreshed });
    const after = try benchmark.verifyBenchmarkCache(
        allocator,
        fixture.io,
        cache.cache,
        stable,
        &fixture.context,
    );
    try std.testing.expectEqualStrings(
        before.object_inventory_sha256,
        after.object_inventory_sha256,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        before.manifest_inventory_sha256,
        after.manifest_inventory_sha256,
    ));
}

test "the lock set fails closed on a cache miss" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const cache = try makeCache(&fixture, null);
    const inventory = try benchmark.verifyWarmCache(
        allocator,
        fixture.io,
        cache.cache,
        &fixture.context,
    );
    const locks = try makeLocks(&fixture, cache.package_digest);
    const verified = try benchmark.verifyLockSet(
        allocator,
        fixture.io,
        locks,
        &inventory,
        &fixture.context,
    );
    try std.testing.expectEqual(benchmark.package_roots.len, verified.locks.len);

    const filename = try benchmark.lockFilename(allocator, benchmark.package_roots[0]);
    const target = try std.fs.path.join(allocator, &.{ locks, filename });
    const contents = try fixture.read(target);
    const mutated = try std.mem.replaceOwned(
        u8,
        allocator,
        contents,
        cache.package_digest,
        "f" ** 64,
    );
    try Dir.cwd().writeFile(fixture.io, .{ .sub_path = target, .data = mutated });
    try expectFailure(benchmark.verifyLockSet(
        allocator,
        fixture.io,
        locks,
        &inventory,
        &fixture.context,
    ));
    try expectContains(fixture.message(), "package cache miss(es)");
}

test "timing schema ingestion preserves every phase value" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const path = try fixture.write(
        &.{"timing.json"},
        try timingDocument(allocator, "success"),
    );
    var timing = try benchmark.loadTiming(allocator, fixture.io, path, &fixture.context);
    try std.testing.expectEqual(benchmark.phase_order.len, timing.values.count());
    for (benchmark.phase_order) |phase| try std.testing.expect(timing.get(phase) != null);

    const negative = try std.mem.replaceOwned(
        u8,
        allocator,
        try timingDocument(allocator, "success"),
        "\"elapsed_ns\": 1,",
        "\"elapsed_ns\": -1,",
    );
    _ = try fixture.write(&.{"timing.json"}, negative);
    try expectFailure(benchmark.loadTiming(
        allocator,
        fixture.io,
        path,
        &fixture.context,
    ));
}

test "timing schema requires a successful raw materialization" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const path = try fixture.write(
        &.{"timing.json"},
        try timingDocument(allocator, "skipped"),
    );
    try expectFailure(benchmark.loadTiming(
        allocator,
        fixture.io,
        path,
        &fixture.context,
    ));
}

fn writeSizedFile(fixture: *Fixture, path: []const u8, size: u64) !void {
    const file = try Dir.cwd().createFile(fixture.io, path, .{});
    defer file.close(fixture.io);
    try file.setLength(fixture.io, size);
}

test "raw output requires an exact regular 5 GiB file" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const raw_output = try fixture.path(&.{benchmark.raw_asset_name});
    try writeSizedFile(&fixture, raw_output, @intCast(benchmark.virtual_size));
    const info = try fixture.write(&.{"raw-info.json"}, try std.fmt.allocPrint(allocator,
        \\{{"filename": "{s}", "format": "raw", "virtual-size": {d},
        \\  "actual-size": {d}, "subformat": null, "backing-filename": null,
        \\  "format-specific": null}}
    , .{ raw_output, benchmark.virtual_size, benchmark.virtual_size }));

    const record = try benchmark.validateRawOutput(
        allocator,
        fixture.io,
        raw_output,
        info,
        &fixture.context,
    );
    try std.testing.expectEqual(benchmark.virtual_size, record.bytes);
    const rendered = try record.toJson(allocator);
    try std.testing.expectEqualStrings(
        benchmark.raw_asset_name,
        rendered.object.get("filename").?.string,
    );
    try std.testing.expectEqual(false, rendered.object.get("byte_hash_recorded").?.bool);

    try writeSizedFile(&fixture, raw_output, @intCast(benchmark.virtual_size - 1));
    try expectFailure(benchmark.validateRawOutput(
        allocator,
        fixture.io,
        raw_output,
        info,
        &fixture.context,
    ));

    try Dir.cwd().deleteFile(fixture.io, raw_output);
    const target = try fixture.path(&.{"raw-target"});
    try writeSizedFile(&fixture, target, @intCast(benchmark.virtual_size));
    try Dir.cwd().symLink(fixture.io, target, raw_output, .{});
    try expectFailure(benchmark.validateRawOutput(
        allocator,
        fixture.io,
        raw_output,
        info,
        &fixture.context,
    ));
}

test "the median is integer and stable" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    try std.testing.expectEqual(@as(i64, 5), try benchmark.medianInt(
        allocator,
        &.{ 9, 1, 5 },
        &fixture.context,
    ));
    try std.testing.expectEqual(@as(i64, 6), try benchmark.medianInt(
        allocator,
        &.{ 10, 2 },
        &fixture.context,
    ));
    try expectFailure(benchmark.medianInt(allocator, &.{}, &fixture.context));
}

test "correctness comparison rejects any contract change" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const reference = try fixture.parse(
        \\{"closure": "a", "acceptance": {"status": "success"}}
    );
    try benchmark.compareCorrectness(
        allocator,
        reference,
        try fixture.parse(
            \\{"closure": "a", "acceptance": {"status": "success"}}
        ),
        &fixture.context,
    );
    try expectFailure(benchmark.compareCorrectness(
        allocator,
        reference,
        try fixture.parse(
            \\{"closure": "b", "acceptance": {"status": "success"}}
        ),
        &fixture.context,
    ));
    try expectContains(fixture.message(), "$.closure: reference=\"a\", candidate=\"b\"");
}

test "correctness diagnostics report all safe field paths" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    try expectFailure(benchmark.compareCorrectness(
        allocator,
        try fixture.parse(
            \\{"profile": {"source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            \\ "acceptance": {"command": "/private/reference/signing-key.pem"}}
        ),
        try fixture.parse(
            \\{"profile": {"source_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            \\ "acceptance": {"command": "/private/candidate/signing-key.pem"}}
        ),
        &fixture.context,
    ));
    const message = fixture.message();
    try expectContains(message, "$.acceptance.command");
    try expectContains(message, "$.profile.source_sha256");
    try expectContains(message, "a" ** 64);
    try expectContains(message, "b" ** 64);
    try expectContains(message, "<absolute-path sha256=");
    try expectExcludes(message, "/private/");
}

test "transaction correctness uses a semantic identity" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const lock_digest = "b" ** 64;
    const transaction_digests = [_][]const u8{ "a" ** 64, "c" ** 64 };
    const run_names = [_][]const u8{ "run-warmup", "run-measured-01" };
    var contracts: [2]Value = undefined;
    var files: [2]Value = undefined;
    var paths: [2][]const u8 = undefined;

    for (run_names, transaction_digests, 0..) |run_name, transaction_digest, index| {
        const run_root = try fixture.path(&.{ run_name, "work", "root-stage-0" });
        const document = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/transaction-result-v1",
            \\  "version": 1, "target_architecture": "arm64",
            \\  "lock_sha256": "{s}", "digest_sha256": "{s}",
            \\  "outcome": "succeeded",
            \\  "commands": [{{"argv": ["dpkg", "--root={s}"],
            \\                "command_sha256": "{s}"}}],
            \\  "final_verification": {{"status": "exact_match"}}}}
        , .{ lock_digest, transaction_digest, run_root, transaction_digest });
        const name = try std.fmt.allocPrint(allocator, "{s}.json", .{run_name});
        paths[index] = try fixture.write(&.{name}, document);
        const binding = try fixture.parse(try std.fmt.allocPrint(allocator,
            \\{{"sha256": "{s}", "digest_sha256": "{s}"}}
        , .{
            try hexDigest(allocator, document),
            transaction_digest,
        }));
        const evidence = try benchmark.validateTransaction(
            allocator,
            fixture.io,
            paths[index],
            binding,
            lock_digest,
            benchmark.package_roots[0],
            &fixture.context,
        );
        contracts[index] = evidence.contract;
        files[index] = evidence.file;
    }

    // Two runs stage into different directories, so the file and transaction
    // digests differ while the semantic contract must not.
    var reference_list = std.json.Array.init(allocator);
    try reference_list.append(contracts[0]);
    var candidate_list = std.json.Array.init(allocator);
    try candidate_list.append(contracts[1]);
    const reference = try wrapProvenance(allocator, .{ .array = reference_list });
    const candidate = try wrapProvenance(allocator, .{ .array = candidate_list });
    try benchmark.compareCorrectness(allocator, reference, candidate, &fixture.context);

    try std.testing.expect(contracts[0].object.get("file_sha256") == null);
    try std.testing.expect(contracts[0].object.get("semantic_digest_sha256") != null);
    try std.testing.expect(!std.mem.eql(
        u8,
        files[0].object.get("file_sha256").?.string,
        files[1].object.get("file_sha256").?.string,
    ));
    try std.testing.expectEqualStrings(
        transaction_digests[0],
        files[0].object.get("transaction_digest_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        transaction_digests[1],
        files[1].object.get("transaction_digest_sha256").?.string,
    );

    // A file hash or a lock the binding does not agree with is a failure, not
    // a difference to be compared later.
    try expectFailure(benchmark.validateTransaction(
        allocator,
        fixture.io,
        paths[0],
        try fixture.parse(
            \\{"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            \\ "digest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        ),
        lock_digest,
        benchmark.package_roots[0],
        &fixture.context,
    ));
    try expectFailure(benchmark.validateTransaction(
        allocator,
        fixture.io,
        paths[0],
        try fixture.parse(try std.fmt.allocPrint(allocator,
            \\{{"sha256": "{s}", "digest_sha256": "{s}"}}
        , .{
            files[0].object.get("file_sha256").?.string,
            transaction_digests[0],
        })),
        "e" ** 64,
        benchmark.package_roots[0],
        &fixture.context,
    ));

    const mutations = [_][2][]const u8{
        .{ "semantic_digest_sha256", "c" ** 64 },
        .{ "lock_sha256", "d" ** 64 },
    };
    for (mutations) |mutation| {
        var mutated = std.json.ObjectMap.empty;
        var entries = contracts[1].object.iterator();
        while (entries.next()) |entry| {
            try mutated.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        try mutated.put(allocator, mutation[0], .{ .string = mutation[1] });
        var list = std.json.Array.init(allocator);
        try list.append(.{ .object = mutated });
        try expectFailure(benchmark.compareCorrectness(
            allocator,
            reference,
            try wrapProvenance(allocator, .{ .array = list }),
            &fixture.context,
        ));
    }

    // A changed command is a changed meaning even when the recorded digests
    // are untouched.
    const changed_source = try fixture.read(paths[1]);
    const changed = try std.mem.replaceOwned(
        u8,
        allocator,
        changed_source,
        "\"dpkg\",",
        "\"dpkg\", \"--force-confnew\",",
    );
    const changed_path = try fixture.write(&.{"changed-command.json"}, changed);
    const changed_evidence = try benchmark.validateTransaction(
        allocator,
        fixture.io,
        changed_path,
        try fixture.parse(try std.fmt.allocPrint(allocator,
            \\{{"sha256": "{s}", "digest_sha256": "{s}"}}
        , .{ try hexDigest(allocator, changed), transaction_digests[1] })),
        lock_digest,
        benchmark.package_roots[0],
        &fixture.context,
    );
    var changed_list = std.json.Array.init(allocator);
    try changed_list.append(changed_evidence.contract);
    try expectFailure(benchmark.compareCorrectness(
        allocator,
        reference,
        try wrapProvenance(allocator, .{ .array = changed_list }),
        &fixture.context,
    ));
}

fn wrapProvenance(allocator: Allocator, contracts: Value) !Value {
    var provenance = std.json.ObjectMap.empty;
    try provenance.put(allocator, "transaction_provenance", contracts);
    var root = std.json.ObjectMap.empty;
    try root.put(allocator, "provenance", .{ .object = provenance });
    return .{ .object = root };
}

test "correctness rejects each semantic contract change" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const reference_text =
        \\{"profile": {"source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        \\ "image": {"format": "qcow2", "compression_type": "zstd",
        \\           "virtual_size": 5368709120},
        \\ "raw_output": {"format": "raw", "virtual_size": 5368709120,
        \\                "structural_validation": "miz-check-and-info"},
        \\ "provenance": {
        \\   "closure_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\   "transaction_provenance": [
        \\     {"semantic_digest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\      "lock_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],
        \\   "signing": {"certificate_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}}
    ;
    const mutations = [_][2][]const u8{
        .{
            "\"source_sha256\": \"" ++ "a" ** 64 ++ "\"",
            "\"source_sha256\": \"" ++ "f" ** 64 ++ "\"",
        },
        .{
            "\"closure_sha256\": \"" ++ "b" ** 64 ++ "\"",
            "\"closure_sha256\": \"" ++ "f" ** 64 ++ "\"",
        },
        .{
            "\"semantic_digest_sha256\": \"" ++ "c" ** 64 ++ "\"",
            "\"semantic_digest_sha256\": \"" ++ "f" ** 64 ++ "\"",
        },
        .{
            "\"lock_sha256\": \"" ++ "d" ** 64 ++ "\"",
            "\"lock_sha256\": \"" ++ "f" ** 64 ++ "\"",
        },
        .{
            "\"certificate_sha256\": \"" ++ "e" ** 64 ++ "\"",
            "\"certificate_sha256\": \"" ++ "f" ** 64 ++ "\"",
        },
        .{ "\"compression_type\": \"zstd\"", "\"compression_type\": \"none\"" },
        .{
            "\"structural_validation\": \"miz-check-and-info\"",
            "\"structural_validation\": \"size-only\"",
        },
    };
    for (mutations) |mutation| {
        const candidate_text = try std.mem.replaceOwned(
            u8,
            allocator,
            reference_text,
            mutation[0],
            mutation[1],
        );
        try std.testing.expect(!std.mem.eql(u8, reference_text, candidate_text));
        try expectFailure(benchmark.compareCorrectness(
            allocator,
            try fixture.parse(reference_text),
            try fixture.parse(candidate_text),
            &fixture.context,
        ));
    }
}

fn summaryRun(
    allocator: Allocator,
    name: []const u8,
    kind: []const u8,
    total: i64,
    wall: i64,
) !benchmark.RunRecord {
    var values: std.StringArrayHashMapUnmanaged(i64) = .empty;
    for (benchmark.phase_order) |phase| try values.put(allocator, phase, 10);
    try values.put(allocator, "total_runtime", total);
    return .{
        .name = name,
        .kind = kind,
        .timing_values = values,
        .resources = .{
            .status = "success",
            .exit_code = 0,
            .wall_ns = wall,
            .user_ns = 8,
            .system_ns = 2,
            .peak_rss_bytes = 100,
            .read_bytes = 200,
            .write_bytes = 300,
            .block_inputs = 4,
            .block_outputs = 5,
            .io_bytes_source = "linux-proc-descendant-sampling",
        },
        .correctness_sha256 = "a" ** 64,
        .image_sha256 = "0" ** 64,
        .image_bytes = 1,
        .raw_output = .{
            .bytes = benchmark.virtual_size,
            .retention_policy = "delete-after-validation",
        },
        .evidence = "run/evidence",
        .cleanup = &.{},
    };
}

test "summary generation uses three measured medians" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const runs = [_]benchmark.RunRecord{
        try summaryRun(allocator, "run-0", "warmup", 100, 100),
        try summaryRun(allocator, "run-1", "measured", 30, 30),
        try summaryRun(allocator, "run-2", "measured", 10, 10),
        try summaryRun(allocator, "run-3", "measured", 20, 20),
    };
    const summary = try benchmark.buildSummary(
        allocator,
        &runs,
        "b" ** 40,
        try fixture.parse(
            \\{"machine": "aarch64"}
        ),
        try fixture.parse(
            \\{"inventory_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        ),
        "d" ** 64,
        try fixture.parse("[]"),
        &fixture.context,
    );

    const medians = summary.object.get("medians").?;
    try std.testing.expectEqual(@as(i64, 20), medians.object
        .get("phase_elapsed_ns").?.object.get("total_runtime").?.integer);
    try std.testing.expectEqual(@as(i64, 20), medians.object
        .get("resources").?.object.get("wall_ns").?.integer);

    const first_run = summary.object.get("runs").?.array.items[0];
    try std.testing.expectEqual(
        benchmark.virtual_size,
        first_run.object.get("raw_output").?.object.get("virtual_size").?.integer,
    );
    try std.testing.expectEqual(false, first_run.object
        .get("raw_output").?.object.get("byte_reproducibility_compared").?.bool);

    const readable = try benchmark.readableSummary(allocator, summary);
    try expectContains(readable, "Status: valid");
    try expectContains(readable, "Median total phase time");
    try expectContains(readable, "not compared");
}

/// Writes a known name into a `utsname` field, which is a fixed-size,
/// NUL-terminated character array.
fn setUtsField(field: []u8, value: []const u8) void {
    @memset(field, 0);
    @memcpy(field[0..value.len], value);
}

/// Builds the host document from a `utsname` that lives several frames below
/// the caller, so the storage its strings were read from is guaranteed to be
/// dead by the time the caller inspects them.
fn hostDocumentFromDeepFrame(allocator: Allocator, depth: usize) !Value {
    if (depth > 0) return hostDocumentFromDeepFrame(allocator, depth - 1);
    var uts = std.mem.zeroes(std.posix.utsname);
    setUtsField(&uts.sysname, "Linux");
    setUtsField(&uts.release, "6.14.0-1234-benchmark");
    setUtsField(&uts.machine, "aarch64");
    return benchmark.hostDocument(allocator, &uts, "0.16.0", 8);
}

/// Overwrites the stack region the frames above used, so a document that had
/// borrowed a `utsname` there would now read the pattern instead.
fn clobberStack(depth: usize) u8 {
    var scratch: [8192]u8 = undefined;
    for (&scratch, 0..) |*byte, index| {
        byte.* = @truncate(index *% 251 +% depth +% 1);
    }
    const carry: u8 = if (depth == 0) 0 else clobberStack(depth - 1);
    std.mem.doNotOptimizeAway(&scratch);
    return scratch[scratch.len - 1] +% carry;
}

test "the recorded host identity outlives the utsname it was read from" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();

    const document = try hostDocumentFromDeepFrame(allocator, 6);
    std.mem.doNotOptimizeAway(clobberStack(24));

    const fields = [_][2][]const u8{
        .{ "system", "Linux" },
        .{ "kernel", "6.14.0-1234-benchmark" },
        .{ "machine", "aarch64" },
        .{ "zig", "0.16.0" },
    };
    for (fields) |field| {
        const value = document.object.get(field[0]) orelse return error.TestMissingField;
        try std.testing.expect(value == .string);
        try std.testing.expectEqualStrings(field[1], value.string);
    }
    try std.testing.expectEqual(@as(i64, 8), document.object.get("cpu_count").?.integer);

    // The summary embeds this document, so it must also survive being
    // serialized after the frame is gone.
    const summary = try benchmark.buildSummary(
        allocator,
        &.{
            try summaryRun(allocator, "run-0", "warmup", 100, 100),
            try summaryRun(allocator, "run-1", "measured", 30, 30),
            try summaryRun(allocator, "run-2", "measured", 10, 10),
            try summaryRun(allocator, "run-3", "measured", 20, 20),
        },
        "b" ** 40,
        document,
        try fixture.parse("{}"),
        "d" ** 64,
        try fixture.parse("[]"),
        &fixture.context,
    );
    std.mem.doNotOptimizeAway(clobberStack(24));
    const path = try fixture.path(&.{"benchmark-summary.json"});
    try benchmark.writeJson(allocator, fixture.io, path, summary);
    const written = try fixture.read(path);
    try expectContains(written, "\"machine\": \"aarch64\"");
    try expectContains(written, "\"kernel\": \"6.14.0-1234-benchmark\"");
    try expectContains(written, "\"system\": \"Linux\"");
}

test "a summary requires exactly three measured runs" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const runs = [_]benchmark.RunRecord{
        try summaryRun(allocator, "run-0", "warmup", 100, 100),
        try summaryRun(allocator, "run-1", "measured", 30, 30),
    };
    try expectFailure(benchmark.buildSummary(
        allocator,
        &runs,
        "b" ** 40,
        try fixture.parse("{}"),
        try fixture.parse("{}"),
        "d" ** 64,
        try fixture.parse("[]"),
        &fixture.context,
    ));
}

test "seconds are rendered with three fractional digits" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { value: ?i64, text: []const u8 }{
        .{ .value = null, .text = "unavailable" },
        .{ .value = 0, .text = "0.000 s" },
        .{ .value = 1_500_000, .text = "0.002 s" },
        .{ .value = 530_000_000_000, .text = "530.000 s" },
        .{ .value = 1_234_567_890, .text = "1.235 s" },
    };
    for (cases) |case| {
        const rendered = try benchmark.formatSeconds(allocator, case.value);
        defer if (case.value != null) allocator.free(rendered);
        try std.testing.expectEqualStrings(case.text, rendered);
    }
}

test "image info must describe a standalone zstd QCOW2 of the exact size" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const valid = try std.fmt.allocPrint(allocator,
        \\{{"format": "qcow2", "virtual-size": {d}, "backing-filename": null,
        \\  "format-specific": {{"type": "qcow2",
        \\                      "data": {{"compression-type": "zstd"}}}}}}
    , .{benchmark.virtual_size});
    const path = try fixture.write(&.{"image-info.json"}, valid);
    const contract = try benchmark.validateImageInfo(
        allocator,
        fixture.io,
        path,
        &fixture.context,
    );
    try std.testing.expectEqualStrings(
        "zstd",
        contract.object.get("compression_type").?.string,
    );

    const mutations = [_][2][]const u8{
        .{ "\"format\": \"qcow2\"", "\"format\": \"raw\"" },
        .{ "\"compression-type\": \"zstd\"", "\"compression-type\": \"zlib\"" },
        .{ "\"backing-filename\": null", "\"backing-filename\": \"/base.qcow2\"" },
        .{ "\"virtual-size\": 5368709120", "\"virtual-size\": 5368709121" },
    };
    for (mutations) |mutation| {
        const mutated = try std.mem.replaceOwned(
            u8,
            allocator,
            valid,
            mutation[0],
            mutation[1],
        );
        try std.testing.expect(!std.mem.eql(u8, valid, mutated));
        _ = try fixture.write(&.{"image-info.json"}, mutated);
        try expectFailure(benchmark.validateImageInfo(
            allocator,
            fixture.io,
            path,
            &fixture.context,
        ));
    }
}

test "staging verification requires the warm cache and the whole lock set" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const input_root = try fixture.mkdir(&.{"inputs"});
    const debz_inputs = try fixture.mkdir(&.{ "inputs", "debz-inputs" });
    const cache = try makeCache(&fixture, debz_inputs);
    const staged_cache = try fixture.path(&.{ "inputs", "debz-cache" });
    try Dir.cwd().rename(cache.cache, Dir.cwd(), staged_cache, fixture.io);
    const locks = try makeLocks(&fixture, cache.package_digest);
    const staged_locks = try fixture.path(&.{ "inputs", "locks" });
    try Dir.cwd().rename(locks, Dir.cwd(), staged_locks, fixture.io);

    try benchmark.verifyStaging(allocator, fixture.io, input_root, &fixture.context);

    const removed = try std.fs.path.join(allocator, &.{
        staged_locks,
        try benchmark.lockFilename(allocator, benchmark.package_roots[0]),
    });
    try Dir.cwd().deleteFile(fixture.io, removed);
    try expectFailure(benchmark.verifyStaging(
        allocator,
        fixture.io,
        input_root,
        &fixture.context,
    ));
}

test "the non-regression gate passes, fails, and records missing evidence" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const summary_path = try fixture.path(&.{"benchmark-summary.json"});
    const status_path = try fixture.path(&.{"benchmark-status.json"});
    const gate_path = try fixture.path(&.{"gate.json"});
    const step_summary = try fixture.path(&.{"step-summary.md"});
    const options: benchmark.GateOptions = .{
        .summary = summary_path,
        .status = status_path,
        .output = gate_path,
        .step_summary = step_summary,
        .ceiling_ns = 530_000_000_000,
    };

    // No summary at all: the gate records the status it can see and fails.
    _ = try fixture.write(&.{"benchmark-status.json"},
        \\{"schema": 1, "type": "miz-ubuntu2604-image-benchmark-status",
        \\ "status": "invalid", "error": "preflight failed"}
    );
    try std.testing.expect(!try benchmark.runGate(
        allocator,
        fixture.io,
        options,
        &fixture.context,
    ));
    try expectContains(try fixture.read(gate_path), "\"status\": \"invalid\"");
    try expectContains(try fixture.read(step_summary), "Benchmark did not complete");

    _ = try fixture.write(&.{"benchmark-summary.json"}, try std.fmt.allocPrint(allocator,
        \\{{"status": "valid", "source_commit": "{s}",
        \\  "medians": {{"phase_elapsed_ns": {{"total_runtime": 520000000000,
        \\               "raw_image_materialization": 42000000000}}}}}}
    , .{"b" ** 40}));
    try std.testing.expect(try benchmark.runGate(
        allocator,
        fixture.io,
        options,
        &fixture.context,
    ));
    const passing = try fixture.read(gate_path);
    try expectContains(passing, "\"status\": \"pass\"");
    try expectContains(passing, "\"median_total_ns\": 520000000000");
    try expectContains(passing, "\"ceiling_ns\": 530000000000");
    const rendered = try fixture.read(step_summary);
    try expectContains(rendered, "- Median total: `520.000 s`");
    try expectContains(rendered, "- Gate: **pass**");
    try expectContains(rendered, "- Boot acceptance: unavailable");

    _ = try fixture.write(&.{"benchmark-summary.json"}, try std.fmt.allocPrint(allocator,
        \\{{"status": "valid", "source_commit": "{s}",
        \\  "medians": {{"phase_elapsed_ns": {{"total_runtime": 530000000001,
        \\               "raw_image_materialization": 42000000000}}}}}}
    , .{"b" ** 40}));
    try std.testing.expect(!try benchmark.runGate(
        allocator,
        fixture.io,
        options,
        &fixture.context,
    ));
    try expectContains(try fixture.read(gate_path), "\"status\": \"fail\"");
}

test "the evidence scan fails closed on a candidate it cannot read" {
    // Root bypasses the permission bits this test relies on.
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const evidence_root = try fixture.mkdir(&.{"evidence"});
    const benchmark_root = try fixture.mkdir(&.{"benchmark"});
    const unreadable = try fixture.write(&.{ "evidence", "sealed.log" }, "sealed\n");
    try Dir.cwd().setFilePermissions(fixture.io, unreadable, @enumFromInt(0o000), .{});
    defer Dir.cwd().setFilePermissions(
        fixture.io,
        unreadable,
        @enumFromInt(0o600),
        .{},
    ) catch {};

    try expectFailure(benchmark.scanPrivateMaterial(
        allocator,
        fixture.io,
        evidence_root,
        benchmark_root,
        &fixture.context,
    ));
    try expectContains(fixture.message(), "cannot scan benchmark evidence");
}

test "the evidence scan rejects private key material anywhere it is uploaded" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const evidence_root = try fixture.mkdir(&.{"evidence"});
    const benchmark_root = try fixture.mkdir(&.{"benchmark"});
    _ = try fixture.write(&.{ "evidence", "staging-build.log" }, "built\n");
    _ = try fixture.write(&.{ "benchmark", "benchmark-summary.json" }, "{}\n");
    _ = try fixture.write(
        &.{ "benchmark", "run-measured-01", "evidence", "run-manifest.json" },
        "{}\n",
    );
    try benchmark.scanPrivateMaterial(
        allocator,
        fixture.io,
        evidence_root,
        benchmark_root,
        &fixture.context,
    );

    const leaks = [_][]const []const u8{
        &.{ "evidence", "nested", "leak.log" },
        &.{ "benchmark", "host.json" },
        &.{ "benchmark", "run-measured-01", "evidence", "provenance", "leak.pem" },
    };
    for (leaks) |leak| {
        const path = try fixture.write(
            leak,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nzzz\n",
        );
        try expectFailure(benchmark.scanPrivateMaterial(
            allocator,
            fixture.io,
            evidence_root,
            benchmark_root,
            &fixture.context,
        ));
        try expectContains(fixture.message(), "private material found in evidence");
        try Dir.cwd().deleteFile(fixture.io, path);
    }
}
