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

test "benchmark compiler validation rejects other releases and failed probes" {
    var context: benchmark.Context = .init(std.testing.allocator);
    defer context.deinit();
    try benchmark.validateZigVersion("0.17.0", 0, &context);
    for ([_][]const u8{ "", "0.16.0", "0.17.1", "0.17.0-dev.1", "0.18.0" }) |version| {
        try expectFailure(benchmark.validateZigVersion(version, 0, &context));
        try expectContains(context.message(), "requires exactly Zig 0.17.0");
    }
    try expectFailure(benchmark.validateZigVersion("0.17.0", 1, &context));
}

const digest_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digest_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const digest_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const digest_d = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const digest_e = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const digest_f = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const digest_zero = "0000000000000000000000000000000000000000000000000000000000000000";
const sha512_a = digest_a ++ digest_a;
const commit_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    const packages = try fixture.mkdir(&.{ "cache-fixture", "packages-v2", "objects" });
    const metadata_bytes = "metadata";
    const metadata_digest = try hexDigest(allocator, metadata_bytes);
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = try std.fs.path.join(allocator, &.{ metadata, metadata_digest }),
        .data = metadata_bytes,
    });
    const package_bytes = "package";
    const package_digest = try hexDigest(allocator, package_bytes);
    const package_object = try std.fmt.allocPrint(
        allocator,
        "sha256-{s}",
        .{package_digest},
    );
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = try std.fs.path.join(allocator, &.{ packages, package_object }),
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
    for (benchmark.lock_roots, 0..) |package, index| {
        const digest = try allocator.alloc(u8, 64);
        @memset(digest, std.fmt.digitToChar(@intCast(index + 1), .lower));
        const document = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/exact-closure-lock-v3",
            \\ "version": 3,
            \\ "target_architecture": "arm64",
            \\ "digest_sha256": "{s}",
            \\ "packages": [{{"name": "{s}", "version": "1",
            \\               "architecture": "arm64",
            \\               "archive_identity": {{"digests": [
            \\                 {{"algorithm": "sha256", "digest": "{s}"}},
            \\                 {{"algorithm": "sha512", "digest": "{s}"}}
            \\               ], "sha512_origin": "derived_after_signed_sha256_verify"}}}}]}}
        , .{ digest, package, package_digest, sha512_a });
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
        "-Doptimize=safe",
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

    const package_object = try std.fmt.allocPrint(
        fixture.allocator(),
        "sha256-{s}",
        .{cache.package_digest},
    );
    _ = try fixture.write(
        &.{ "cache-fixture", "packages-v2", "objects", package_object },
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
        digest_f,
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
    try std.testing.expectEqual(benchmark.lock_roots.len, verified.locks.len);
    const final_guest = verified.final_closure.array.items;
    try std.testing.expectEqual(@as(usize, 1), final_guest.len);
    try std.testing.expectEqualStrings(
        benchmark.package_roots[benchmark.package_roots.len - 1],
        final_guest[0].object.get("name").?.string,
    );

    const filename = try benchmark.lockFilename(allocator, benchmark.package_roots[0]);
    const target = try std.fs.path.join(allocator, &.{ locks, filename });
    const contents = try fixture.read(target);
    const mutated = try std.mem.replaceOwned(
        u8,
        allocator,
        contents,
        cache.package_digest,
        digest_f,
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
    try expectContains(message, digest_a);
    try expectContains(message, digest_b);
    try expectContains(message, "<absolute-path sha256=");
    try expectExcludes(message, "/private/");
}

test "transaction correctness uses a semantic identity" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const lock_digest = digest_b;
    const transaction_digests = [_][]const u8{ digest_a, digest_c };
    const attempt_ids = [_][]const u8{ digest_d, digest_e };
    const root_inodes = [_]u64{ 101, 202 };
    const run_names = [_][]const u8{ "run-warmup", "run-measured-01" };
    var contracts: [2]Value = undefined;
    var files: [2]Value = undefined;
    var paths: [2][]const u8 = undefined;

    for (
        run_names,
        transaction_digests,
        attempt_ids,
        root_inodes,
        0..,
    ) |run_name, transaction_digest, attempt_id, root_inode, index| {
        const run_root = try fixture.path(&.{ run_name, "work", "root-stage-0" });
        const document = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/native-transaction-provenance-v2",
            \\  "version": 2, "backend": "native",
            \\  "install_root": "{s}", "attempt_id": "{s}",
            \\  "root_inode": {d}, "program_sha256": "{s}",
            \\  "exact_lock_sha256": "{s}", "final_state_sha256": "{s}",
            \\  "final_state_kind": "package_database_closure_v1",
            \\  "outcome": "succeeded", "digest_sha256": "{s}"}}
        , .{
            run_root,
            attempt_id,
            root_inode,
            digest_a,
            lock_digest,
            digest_f,
            transaction_digest,
        });
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
        digest_e,
        benchmark.package_roots[0],
        &fixture.context,
    ));

    const mutations = [_][2][]const u8{
        .{ "semantic_digest_sha256", digest_c },
        .{ "lock_sha256", digest_d },
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

    // A changed semantic field is a changed meaning even when the recorded
    // digests are untouched.
    const changed_source = try fixture.read(paths[1]);
    const changed = try std.mem.replaceOwned(
        u8,
        allocator,
        changed_source,
        "\"final_state_sha256\": \"" ++ digest_f ++ "\"",
        "\"final_state_sha256\": \"" ++ digest_zero ++ "\"",
    );
    const changed_path = try fixture.write(&.{"changed-transaction.json"}, changed);
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

    try std.testing.expectError(
        error.InvalidDebzTransaction,
        benchmark.semanticTransactionDigest(
            allocator,
            try fixture.parse(
                \\{"schema": "https://debz.dev/schema/native-transaction-provenance-v2",
                \\ "version": 2, "backend": "native"}
            ),
            &fixture.context,
        ),
    );
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
            "\"source_sha256\": \"" ++ digest_a ++ "\"",
            "\"source_sha256\": \"" ++ digest_f ++ "\"",
        },
        .{
            "\"closure_sha256\": \"" ++ digest_b ++ "\"",
            "\"closure_sha256\": \"" ++ digest_f ++ "\"",
        },
        .{
            "\"semantic_digest_sha256\": \"" ++ digest_c ++ "\"",
            "\"semantic_digest_sha256\": \"" ++ digest_f ++ "\"",
        },
        .{
            "\"lock_sha256\": \"" ++ digest_d ++ "\"",
            "\"lock_sha256\": \"" ++ digest_f ++ "\"",
        },
        .{
            "\"certificate_sha256\": \"" ++ digest_e ++ "\"",
            "\"certificate_sha256\": \"" ++ digest_f ++ "\"",
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
        .correctness_sha256 = digest_a,
        .image_sha256 = digest_zero,
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
        commit_b,
        try fixture.parse(
            \\{"machine": "aarch64"}
        ),
        try fixture.parse(
            \\{"inventory_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        ),
        digest_d,
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
    return benchmark.hostDocument(allocator, &uts, "0.17.0", 8);
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
        .{ "zig", "0.17.0" },
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
        commit_b,
        document,
        try fixture.parse("{}"),
        digest_d,
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
        commit_b,
        try fixture.parse("{}"),
        try fixture.parse("{}"),
        digest_d,
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
    , .{commit_b}));
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
    , .{commit_b}));
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
    try Dir.cwd().setFilePermissions(fixture.io, unreadable, @fromBackingInt(@intCast(0o000)), .{});
    defer Dir.cwd().setFilePermissions(
        fixture.io,
        unreadable,
        @fromBackingInt(@intCast(0o600)),
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

test "benchmark cache requirements match debz 0.4.0 repository and configuration identities" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    const debz = @import("debz");
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const debz_inputs = try fixture.mkdir(&.{"debz-inputs"});
    const keyring = try fixture.write(
        &.{ "debz-inputs", "ubuntu-archive-keyring.gpg" },
        "keyring",
    );

    const frozen_source = try std.fmt.allocPrint(
        allocator,
        \\Types: deb
        \\URIs: https://snapshot.ubuntu.com/ubuntu/20261001T000000Z
        \\Suites: resolute
        \\Components: main restricted universe multiverse
        \\Architectures: arm64
        \\Signed-By: {s}
        \\
    ,
        .{keyring},
    );
    const witness_source = try std.fmt.allocPrint(
        allocator,
        \\Types: deb
        \\URIs: https://snapshot.ubuntu.com/ubuntu/20261001T000000Z
        \\Suites: resolute-updates resolute-security
        \\Components: main restricted universe multiverse
        \\Architectures: arm64
        \\Signed-By: {s}
        \\
    ,
        .{keyring},
    );
    const frozen_digest = try debz.repository_refresh.parseFrozenReleaseDigest(
        "sha256:596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834",
    );
    const unbounded: u64 = @intCast(std.math.maxInt(i64));
    const unbounded_deadlines: debz.repository_acquisition.Deadlines = .{
        .connect_ms = unbounded,
        .read_ms = unbounded,
        .overall_ms = unbounded,
    };
    const normalized = try debz.repository_policy.normalize(
        allocator,
        &.{
            .{
                .bytes = frozen_source,
                .format = .deb822,
                .policy = .{
                    .immutability = .{ .kind = .immutable_url },
                    .freshness = .{
                        .frozen_release_with_witnesses = .{
                            .release_digest = frozen_digest,
                        },
                    },
                    .freshness_witnesses = &.{ "resolute-updates", "resolute-security" },
                    .deadlines = unbounded_deadlines,
                },
            },
            .{
                .bytes = witness_source,
                .format = .deb822,
                .policy = .{
                    .immutability = .{ .kind = .immutable_url },
                    .freshness = .{
                        .allow_missing_valid_until_with_max_age_seconds = 31 * 24 * 60 * 60,
                    },
                    .deadlines = unbounded_deadlines,
                },
            },
        },
        "arm64",
        .{},
    );
    try std.testing.expect(normalized == .configuration);
    var configuration = normalized.configuration;
    defer configuration.deinit();

    const requirements = try benchmark.benchmarkCacheRequirements(
        allocator,
        fixture.io,
        debz_inputs,
    );
    try std.testing.expectEqual(@as(usize, 12), configuration.repositories.len);
    try std.testing.expectEqual(@as(usize, 25), requirements.len);

    for (configuration.repositories, 0..) |repository, index| {
        const expected_id = benchmark.debzRepositoryId(
            repository.suite,
            repository.component,
            keyring,
        );
        try std.testing.expectEqualStrings(&expected_id, repository.id.slice());
        const refresh_req = requirements[index * 2];
        const policy_req = requirements[index * 2 + 1];
        try std.testing.expectEqualStrings(repository.id.slice(), refresh_req.repository);
        try std.testing.expectEqualStrings(
            if (std.mem.eql(u8, repository.suite, "resolute"))
                "repository-refresh-v5"
            else
                "repository-refresh-v4",
            refresh_req.snapshot,
        );
        try std.testing.expectEqualStrings(repository.id.slice(), policy_req.repository);
        try std.testing.expectEqualStrings("repository-policy-v1", policy_req.snapshot);
    }
    const aggregate_req = requirements[requirements.len - 1];
    try std.testing.expectEqualStrings("repository-aggregate", aggregate_req.phase);
    try std.testing.expectEqualStrings(
        configuration.identity.slice(),
        aggregate_req.repository,
    );
    try std.testing.expectEqualStrings("multi-repository-v1", aggregate_req.snapshot);
}

const canonical_manifest_xz_base64 =
    "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";

fn decompressManifestAlloc(allocator: Allocator) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const compressed = try allocator.alloc(
        u8,
        try decoder.calcSizeForSlice(canonical_manifest_xz_base64),
    );
    try decoder.decode(compressed, canonical_manifest_xz_base64);
    var input = std.Io.Reader.fixed(compressed);
    var decompressor = try std.compress.xz.Decompress.init(&input, allocator, &.{});
    defer decompressor.deinit();
    return decompressor.reader.allocRemaining(allocator, .unlimited);
}

const ProvenanceFixture = struct {
    dir: []const u8,
    build_path: []const u8,
    build_json: []const u8,
    budget_path: []const u8,
    budget_json: []const u8,
    lock_set: benchmark.LockSet,
};

fn makeProvenanceFixture(fixture: *Fixture) !ProvenanceFixture {
    const allocator = fixture.allocator();
    const cache = try makeCache(fixture, null);
    const inventory = try benchmark.verifyWarmCache(
        allocator,
        fixture.io,
        cache.cache,
        &fixture.context,
    );
    const locks = try makeLocks(fixture, cache.package_digest);
    const lock_set = try benchmark.verifyLockSet(
        allocator,
        fixture.io,
        locks,
        &inventory,
        &fixture.context,
    );

    const provenance = try fixture.mkdir(&.{"provenance-fixture"});
    const sums_bytes = try Dir.cwd().readFileAlloc(
        fixture.io,
        "scripts/fixtures/openpgp/canonical-SHA256SUMS",
        allocator,
        .limited(64 * 1024),
    );
    _ = try fixture.write(&.{ "provenance-fixture", "SHA256SUMS" }, sums_bytes);
    const sig_bytes = try Dir.cwd().readFileAlloc(
        fixture.io,
        "scripts/fixtures/openpgp/canonical-SHA256SUMS.gpg",
        allocator,
        .limited(64 * 1024),
    );
    _ = try fixture.write(&.{ "provenance-fixture", "SHA256SUMS.gpg" }, sig_bytes);
    const manifest_bytes = try decompressManifestAlloc(allocator);
    _ = try fixture.write(
        &.{ "provenance-fixture", benchmark.manifest_name },
        manifest_bytes,
    );

    // Measure a complete miniature root and emit both size_inventory and
    // size_budget through the real writers so their schemas and digests match
    // what `build_generalized_ubuntu2604.zig` writes for `baremetal`.
    const measured_root = try fixture.mkdir(&.{"measured-root"});
    const root_files = [_]struct { path: []const u8, contents: []const u8 }{
        .{
            .path = benchmark.size_inventory.package_lock_path,
            .contents = "alpha\t1.0-1\tarm64\n",
        },
        .{
            .path = "/var/lib/dpkg/info/alpha.list",
            .contents = "/boot\n/boot/vmlinuz-" ++ benchmark.baremetal_kernel_release ++
                "\n/etc\n/usr\n/usr/bin\n/usr/bin/alpha\n/var\n/var/lib\n",
        },
        .{ .path = "/usr/bin/alpha", .contents = "owned payload" },
        .{ .path = "/etc/ld.so.cache", .contents = "generated cache" },
        .{
            .path = "/boot/vmlinuz-" ++ benchmark.baremetal_kernel_release,
            .contents = "kernel",
        },
    };
    for (root_files) |file| {
        const target = try std.fs.path.join(
            allocator,
            &.{ measured_root, file.path[1..] },
        );
        if (std.fs.path.dirname(target)) |parent| {
            try Dir.cwd().createDirPath(fixture.io, parent);
        }
        try Dir.cwd().writeFile(fixture.io, .{
            .sub_path = target,
            .data = file.contents,
        });
    }

    var inv_diag: benchmark.size_inventory.Diagnostic = .{};
    var report = try benchmark.size_inventory.Report.init(allocator, .{
        .architecture = .aarch64,
        .flavor = .baremetal,
    });
    const section = try benchmark.size_inventory.measureRootBuild(
        report.allocator(),
        allocator,
        fixture.io,
        .{
            .root_path = measured_root,
            .flavor = .baremetal,
            .kernel_release = benchmark.baremetal_kernel_release,
        },
        &inv_diag,
    );
    try report.addPhase(.root_build, section, &inv_diag);
    try report.addPhase(
        .image_build,
        try benchmark.size_inventory.imageBuildValue(
            report.allocator(),
            .{
                .virtual_size = @intCast(benchmark.virtual_size),
                .root = .{
                    .block_size = 4096,
                    .total_blocks = 1_179_131,
                    .free_blocks = 900_000,
                    .total_inodes = 294_912,
                    .free_inodes = 280_000,
                },
                .uki_bytes = 58_039_112,
                .esp_partition_bytes = 512 * 1024 * 1024,
                .esp_total_bytes = 510 * 1024 * 1024,
                .esp_free_bytes = 450 * 1024 * 1024,
            },
            &inv_diag,
        ),
        &inv_diag,
    );
    try report.addPhase(
        .publication,
        try benchmark.size_inventory.publicationValue(
            report.allocator(),
            .{
                .artifact_name = benchmark.asset_name,
                .compressed_artifact_bytes = 256 * 1024 * 1024,
                .qcow2_allocated_bytes = 512 * 1024 * 1024,
            },
        ),
        &inv_diag,
    );
    const inventory_name = "ubuntu2604-size-inventory-baremetal-aarch64.json";
    const inventory_json = try report.toJsonAlloc(allocator);
    _ = try fixture.write(&.{ "provenance-fixture", inventory_name }, inventory_json);
    const inventory_sha256 = try hexDigest(allocator, inventory_json);

    const parsed_inventory = try fixture.parse(inventory_json);
    var budget_diag: benchmark.size_budget.Diagnostic = .{};
    var evaluation = try benchmark.size_budget.evaluate(
        allocator,
        parsed_inventory,
        .{
            .architecture = benchmark.architecture,
            .flavor = benchmark.flavor,
        },
        &budget_diag,
    );
    const budget_name = "ubuntu2604-size-budget-baremetal-aarch64.json";
    const budget_path = try std.fs.path.join(
        allocator,
        &.{ provenance, budget_name },
    );
    try benchmark.size_budget.write(
        allocator,
        fixture.io,
        budget_path,
        &evaluation,
        &budget_diag,
    );
    const budget_json = try fixture.read(budget_path);
    const budget_sha256 = try hexDigest(allocator, budget_json);

    var guest_transactions: std.ArrayList(u8) = .empty;
    var stage_transactions: std.ArrayList(u8) = .empty;
    for (benchmark.lock_roots, 0..) |package, index| {
        const lock_record = lock_set.find(package).?;
        const source_lock = try std.fs.path.join(
            allocator,
            &.{ locks, lock_record.filename },
        );
        const lock_bytes = try fixture.read(source_lock);
        _ = try fixture.write(
            &.{ "provenance-fixture", lock_record.filename },
            lock_bytes,
        );

        const tx_digest = try allocator.alloc(u8, 64);
        @memset(tx_digest, 'a' + @as(u8, @intCast(index)));
        const tx_name = try std.fmt.allocPrint(
            allocator,
            "debz-transaction-provenance-{s}-arm64.json",
            .{package},
        );
        const tx_doc = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/native-transaction-provenance-v2",
            \\  "version": 2, "backend": "native",
            \\  "install_root": "/bench/run-warmup/work/root-stage-{d}",
            \\  "attempt_id": "{s}", "root_inode": 100,
            \\  "exact_lock_sha256": "{s}",
            \\  "final_state_kind": "package_database_closure_v1",
            \\  "outcome": "succeeded", "digest_sha256": "{s}"}}
        , .{ index, digest_a, lock_record.digest_sha256, tx_digest });
        _ = try fixture.write(&.{ "provenance-fixture", tx_name }, tx_doc);
        const tx_file_sha256 = try hexDigest(allocator, tx_doc);

        const entry_json = try std.fmt.allocPrint(allocator,
            \\{{"package": "{s}",
            \\  "exact_lock": {{"filename": "{s}", "sha256": "{s}", "digest_sha256": "{s}"}},
            \\  "transaction_provenance": {{"filename": "{s}", "sha256": "{s}",
            \\                              "digest_sha256": "{s}", "lock_sha256": "{s}"}}}}
        , .{
            package,
            lock_record.filename,
            lock_record.file_sha256,
            lock_record.digest_sha256,
            tx_name,
            tx_file_sha256,
            tx_digest,
            lock_record.digest_sha256,
        });
        if (index < benchmark.package_roots.len) {
            if (guest_transactions.items.len > 0) {
                try guest_transactions.appendSlice(allocator, ", ");
            }
            try guest_transactions.appendSlice(allocator, entry_json);
        } else {
            if (stage_transactions.items.len > 0) {
                try stage_transactions.appendSlice(allocator, ", ");
            }
            try stage_transactions.appendSlice(allocator, entry_json);
        }
    }

    _ = try fixture.write(
        &.{ "provenance-fixture", "ubuntu2604-boot-input-evidence.json" },
        try std.fmt.allocPrint(allocator,
            \\{{"schema": 1, "type": "miz-ubuntu2604-boot-input-evidence",
            \\  "architecture": "aarch64",
            \\  "kernel_release": "{s}",
            \\  "package_lock": "/var/lib/miz/ubuntu2604-package-lock.tsv",
            \\  "package_lock_sha256": "{s}"}}
        , .{ benchmark.baremetal_kernel_release, digest_b }),
    );
    _ = try fixture.write(
        &.{ "provenance-fixture", "uki-signing-baremetal-aarch64.json" },
        try std.fmt.allocPrint(allocator,
            \\{{"schema": 1, "type": "miz-uki-signing",
            \\  "architecture": "aarch64", "flavor": "baremetal",
            \\  "signer_mode": "local-key",
            \\  "certificate_sha256": "{s}",
            \\  "signature_verification": "success",
            \\  "uki_stub": {{"sha256": "{s}"}}}}
        , .{ digest_c, digest_d }),
    );

    const build_json = try std.fmt.allocPrint(allocator,
        \\{{"schema": 1, "type": "miz-ubuntu2604-build-provenance",
        \\  "architecture": "aarch64", "flavor": "baremetal", "release": "26.04",
        \\  "size_inventory": {{"filename": "{s}", "sha256": "{s}"}},
        \\  "size_budget": {{"filename": "{s}", "sha256": "{s}"}},
        \\  "virtual_size": {d},
        \\  "minimum_root_free_bytes": 1073741824,
        \\  "validated_root_free_bytes": 2147483648,
        \\  "snapshot": {{"id": "release-20260731",
        \\                "base_url": "https://cloud-images.ubuntu.com/releases/26.04/release-20260731/"}},
        \\  "canonical_key_fingerprint": "{s}",
        \\  "sha256sums_signature_verified": true,
        \\  "disk_layout": {{
        \\    "source": "canonical-gen2-gpt",
        \\    "transform": "arm64-esp-rebuild-v1",
        \\    "esp": {{
        \\      "table_index": 14,
        \\      "first_lba": 2048,
        \\      "last_lba": 1050623,
        \\      "size_bytes": 536870912,
        \\      "fat32": "reformatted-preserve-volume-id",
        \\      "content": "signed-fallback-only"
        \\    }},
        \\    "retired_xbootldr": {{"table_index": 12, "cleared": true}}
        \\  }},
        \\  "artifacts": {{
        \\    "sha256sums": {{"filename": "SHA256SUMS", "sha256": "{s}"}},
        \\    "sha256sums_signature": {{"filename": "SHA256SUMS.gpg", "sha256": "{s}"}},
        \\    "source_image": {{"filename": "{s}", "sha256": "{s}", "role": "signed-gpt-esp-substrate"}},
        \\    "image_manifest": {{"filename": "{s}", "sha256": "{s}"}}
        \\  }},
        \\  "debz": {{
        \\    "api_commit": "{s}",
        \\    "baseline": {{"source": "empty-debz-root", "enforcement": "exact-final-closure"}},
        \\    "package_roots": [
        \\      "linux-modules-7.0.0-2015-nvidia-bos-64k",
        \\      "linux-image-7.0.0-2015-nvidia-bos-64k",
        \\      "openssh-server",
        \\      "sudo",
        \\      "ca-certificates"
        \\    ],
        \\    "transactions": [{s}],
        \\    "build_stage": {{
        \\      "purpose": "initramfs-generation",
        \\      "package_roots": ["initramfs-tools"],
        \\      "transactions": [{s}],
        \\      "initramfs": {{
        \\        "path": "/boot/initrd.img-{s}",
        \\        "kernel_release": "{s}",
        \\        "sha256": "{s}",
        \\        "bytes": 16777216
        \\      }}
        \\    }}
        \\  }}}}
    , .{
        inventory_name,
        inventory_sha256,
        budget_name,
        budget_sha256,
        benchmark.virtual_size,
        benchmark.canonical_fingerprint,
        benchmark.sums_sha256,
        benchmark.sums_signature_sha256,
        benchmark.source_name,
        benchmark.source_sha256,
        benchmark.manifest_name,
        benchmark.manifest_sha256,
        benchmark.debz_api_commit,
        guest_transactions.items,
        stage_transactions.items,
        benchmark.baremetal_kernel_release,
        benchmark.baremetal_kernel_release,
        digest_e,
    });
    const build_path = try fixture.write(
        &.{ "provenance-fixture", "ubuntu2604-build-provenance.json" },
        build_json,
    );
    return .{
        .dir = provenance,
        .build_path = build_path,
        .build_json = build_json,
        .budget_path = budget_path,
        .budget_json = budget_json,
        .lock_set = lock_set,
    };
}

test "provenance validation requires size budget disk layout and initramfs build stage" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const allocator = fixture.allocator();
    const prov = try makeProvenanceFixture(&fixture);

    const validated = try benchmark.validateProvenance(
        allocator,
        fixture.io,
        prov.dir,
        &prov.lock_set,
        digest_c,
        &fixture.context,
    );
    const tx_contracts = validated.contract.object.get("transaction_provenance").?.array.items;
    try std.testing.expectEqual(benchmark.lock_roots.len, tx_contracts.len);
    try std.testing.expectEqualStrings(
        "initramfs-tools",
        tx_contracts[benchmark.package_roots.len].object.get("package").?.string,
    );

    const build_mutations = [_][2][]const u8{
        .{
            "\"ubuntu2604-size-budget-baremetal-aarch64.json\"",
            "\"ubuntu2604-size-budget-core-aarch64.json\"",
        },
        .{
            "\"transform\": \"arm64-esp-rebuild-v1\"",
            "\"transform\": \"preserved\"",
        },
        .{
            "\"last_lba\": 1050623",
            "\"last_lba\": 1050622",
        },
        .{
            "\"cleared\": true",
            "\"cleared\": false",
        },
        .{
            "\"purpose\": \"initramfs-generation\"",
            "\"purpose\": \"guest-root\"",
        },
        .{
            "\"package_roots\": [\"initramfs-tools\"]",
            "\"package_roots\": [\"sudo\"]",
        },
        .{
            "\"path\": \"/boot/initrd.img-7.0.0-2015-nvidia-bos-64k\"",
            "\"path\": \"/boot/initrd.img-generic\"",
        },
        .{
            "\"bytes\": 16777216",
            "\"bytes\": 0",
        },
    };
    for (build_mutations) |mutation| {
        const mutated = try std.mem.replaceOwned(
            u8,
            allocator,
            prov.build_json,
            mutation[0],
            mutation[1],
        );
        try std.testing.expect(!std.mem.eql(u8, prov.build_json, mutated));
        try Dir.cwd().writeFile(fixture.io, .{
            .sub_path = prov.build_path,
            .data = mutated,
        });
        try expectFailure(benchmark.validateProvenance(
            allocator,
            fixture.io,
            prov.dir,
            &prov.lock_set,
            digest_c,
            &fixture.context,
        ));
    }
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = prov.build_path,
        .data = prov.build_json,
    });

    // Tampering with the bound size-budget document must fail closed both on
    // file-digest mismatch and when the digest is re-bound to an invalid result.
    const tampered_budget = try std.mem.replaceOwned(
        u8,
        allocator,
        prov.budget_json,
        "\"result\": \"baseline-recorded\"",
        "\"result\": \"pass\"",
    );
    try std.testing.expect(!std.mem.eql(u8, prov.budget_json, tampered_budget));
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = prov.budget_path,
        .data = tampered_budget,
    });
    try expectFailure(benchmark.validateProvenance(
        allocator,
        fixture.io,
        prov.dir,
        &prov.lock_set,
        digest_c,
        &fixture.context,
    ));
    const rebound_build = try std.mem.replaceOwned(
        u8,
        allocator,
        prov.build_json,
        try hexDigest(allocator, prov.budget_json),
        try hexDigest(allocator, tampered_budget),
    );
    try Dir.cwd().writeFile(fixture.io, .{
        .sub_path = prov.build_path,
        .data = rebound_build,
    });
    try expectFailure(benchmark.validateProvenance(
        allocator,
        fixture.io,
        prov.dir,
        &prov.lock_set,
        digest_c,
        &fixture.context,
    ));
}
