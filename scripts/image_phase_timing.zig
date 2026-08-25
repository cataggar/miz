const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const Phase = enum {
    input_acquisition,
    source_qcow2_setup,
    debz_transaction,
    debz_aggregate,
    initramfs_ext4_import,
    uki_assembly,
    uki_signing,
    qcow2_finalization,
    final_image_validation,
    raw_image_materialization,
    provenance_output,
    total_runtime,
};

pub const Status = enum {
    success,
    failure,
};

const Outcome = enum {
    success,
    failure,
    skipped,
};

const max_records = 64;

const Record = struct {
    phase: Phase,
    item: ?[]const u8,
    elapsed_ns: u64,
    outcome: Outcome,
    error_name: ?[]const u8,
};

/// A fixed-capacity, opt-in recorder. Disabled recorders do not read the
/// clock, allocate memory, or touch the filesystem.
pub const Recorder = struct {
    allocator: Allocator,
    io: Io,
    output_path: ?[]const u8,
    records: [max_records]Record = undefined,
    record_count: usize = 0,

    pub fn init(allocator: Allocator, io: Io, output_path: ?[]const u8) Recorder {
        return .{
            .allocator = allocator,
            .io = io,
            .output_path = output_path,
        };
    }

    pub fn begin(self: *Recorder, phase: Phase, item: ?[]const u8) Scope {
        if (self.output_path == null) return .{
            .recorder = self,
            .phase = phase,
            .item = item,
            .started_ns = 0,
            .enabled = false,
        };
        return .{
            .recorder = self,
            .phase = phase,
            .item = item,
            .started_ns = Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds,
            .enabled = true,
        };
    }

    pub fn skip(self: *Recorder, phase: Phase, item: ?[]const u8) void {
        if (self.output_path == null) return;
        self.append(.{
            .phase = phase,
            .item = item,
            .elapsed_ns = 0,
            .outcome = .skipped,
            .error_name = null,
        });
    }

    pub fn serializeAlloc(self: *const Recorder, status: Status) ![]u8 {
        const JsonRecord = struct {
            name: []const u8,
            item: ?[]const u8,
            elapsed_ns: u64,
            outcome: []const u8,
            error_name: ?[]const u8,
        };
        var json_records: [max_records]JsonRecord = undefined;
        for (self.records[0..self.record_count], 0..) |record, index| {
            json_records[index] = .{
                .name = @tagName(record.phase),
                .item = record.item,
                .elapsed_ns = record.elapsed_ns,
                .outcome = @tagName(record.outcome),
                .error_name = record.error_name,
            };
        }
        const failed = self.firstFailure();
        return std.json.Stringify.valueAlloc(self.allocator, .{
            .schema = @as(u32, 1),
            .type = "miz-ubuntu2604-image-phase-timing",
            .clock = "monotonic",
            .duration_unit = "nanoseconds",
            .status = @tagName(status),
            .failed_phase = if (failed) |record| @tagName(record.phase) else null,
            .failed_item = if (failed) |record| record.item else null,
            .error_name = if (failed) |record| record.error_name else null,
            .phases = json_records[0..self.record_count],
        }, .{ .whitespace = .indent_2 });
    }

    pub fn failedPhase(self: *const Recorder) ?Phase {
        const record = self.firstFailure() orelse return null;
        return record.phase;
    }

    /// Atomically replaces the requested timing file. Every serialization,
    /// write, and rename error is returned to the caller.
    pub fn write(self: *const Recorder, status: Status) !void {
        const output_path = self.output_path orelse return;
        const json = try self.serializeAlloc(status);
        defer self.allocator.free(json);
        const staged_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}.miz-timing-stage",
            .{output_path},
        );
        defer self.allocator.free(staged_path);
        Dir.cwd().deleteFile(self.io, staged_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        errdefer Dir.cwd().deleteFile(self.io, staged_path) catch {};
        try Dir.cwd().writeFile(self.io, .{
            .sub_path = staged_path,
            .data = json,
        });
        try Dir.cwd().rename(staged_path, Dir.cwd(), output_path, self.io);
    }

    fn append(self: *Recorder, record: Record) void {
        std.debug.assert(self.record_count < self.records.len);
        self.records[self.record_count] = record;
        self.record_count += 1;
    }

    fn firstFailure(self: *const Recorder) ?Record {
        for (self.records[0..self.record_count]) |record| {
            if (record.outcome == .failure) return record;
        }
        return null;
    }
};

pub const Scope = struct {
    recorder: *Recorder,
    phase: Phase,
    item: ?[]const u8,
    started_ns: i96,
    enabled: bool,
    finished: bool = false,

    pub fn succeed(self: *Scope) void {
        self.finish(.success, null);
    }

    pub fn fail(self: *Scope, error_name: []const u8) void {
        self.finish(.failure, error_name);
    }

    pub fn end(self: *Scope) void {
        if (!self.finished) self.finish(.failure, null);
    }

    fn finish(self: *Scope, outcome: Outcome, error_name: ?[]const u8) void {
        if (self.finished) return;
        self.finished = true;
        if (!self.enabled) return;
        const finished_ns = Io.Clock.Timestamp.now(self.recorder.io, .awake).raw.nanoseconds;
        const elapsed = finished_ns - self.started_ns;
        self.recorder.append(.{
            .phase = self.phase,
            .item = self.item,
            .elapsed_ns = if (elapsed <= 0)
                0
            else
                std.math.cast(u64, elapsed) orelse std.math.maxInt(u64),
            .outcome = outcome,
            .error_name = error_name,
        });
    }
};

test "disabled recorder has no clock or filesystem output" {
    const io = std.testing.io;
    const path = "test-image-phase-timing-disabled.json";
    Dir.cwd().deleteFile(io, path) catch {};
    var recorder = Recorder.init(std.testing.allocator, io, null);
    var scope = recorder.begin(.source_qcow2_setup, null);
    scope.succeed();
    recorder.skip(.raw_image_materialization, null);
    try recorder.write(.success);
    try std.testing.expectEqual(@as(usize, 0), recorder.record_count);
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, path, .{}),
    );
}

test "schema serialization preserves stable ordering and completeness" {
    var recorder = Recorder.init(std.testing.allocator, std.testing.io, "unused.json");
    var total = recorder.begin(.total_runtime, null);
    var inputs = recorder.begin(.input_acquisition, null);
    inputs.succeed();
    var source = recorder.begin(.source_qcow2_setup, null);
    source.succeed();
    var aggregate = recorder.begin(.debz_aggregate, null);
    var first_transaction = recorder.begin(.debz_transaction, "ubuntu-minimal");
    first_transaction.succeed();
    var second_transaction = recorder.begin(.debz_transaction, "linux-azure");
    second_transaction.succeed();
    aggregate.succeed();
    var initramfs = recorder.begin(.initramfs_ext4_import, null);
    initramfs.succeed();
    var assembly = recorder.begin(.uki_assembly, null);
    assembly.succeed();
    var signing = recorder.begin(.uki_signing, null);
    signing.succeed();
    var finalization = recorder.begin(.qcow2_finalization, null);
    finalization.succeed();
    var validation = recorder.begin(.final_image_validation, null);
    validation.succeed();
    recorder.skip(.raw_image_materialization, null);
    var provenance = recorder.begin(.provenance_output, null);
    provenance.succeed();
    total.succeed();

    const json = try recorder.serializeAlloc(.success);
    defer std.testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(
        @as(i64, 1),
        parsed.value.object.get("schema").?.integer,
    );
    try std.testing.expectEqualStrings(
        "miz-ubuntu2604-image-phase-timing",
        parsed.value.object.get("type").?.string,
    );
    try std.testing.expectEqualStrings(
        "monotonic",
        parsed.value.object.get("clock").?.string,
    );
    const phases = parsed.value.object.get("phases").?.array.items;
    try std.testing.expectEqual(@as(usize, 13), phases.len);
    try std.testing.expectEqualStrings(
        "input_acquisition",
        phases[0].object.get("name").?.string,
    );
    try std.testing.expectEqualStrings(
        "ubuntu-minimal",
        phases[2].object.get("item").?.string,
    );
    try std.testing.expectEqualStrings(
        "debz_aggregate",
        phases[4].object.get("name").?.string,
    );
    try std.testing.expectEqualStrings(
        "skipped",
        phases[10].object.get("outcome").?.string,
    );
    try std.testing.expectEqualStrings(
        "total_runtime",
        phases[12].object.get("name").?.string,
    );
}

test "failure is recorded and timing output errors propagate" {
    const io = std.testing.io;
    const output_path = "test-image-phase-timing-failure.json";
    Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};

    var recorder = Recorder.init(std.testing.allocator, io, output_path);
    const FailureHarness = struct {
        fn run(timing: *Recorder) !void {
            var aggregate = timing.begin(.debz_aggregate, null);
            defer aggregate.end();
            errdefer |err| aggregate.fail(@errorName(err));
            var transaction = timing.begin(.debz_transaction, "linux-azure");
            defer transaction.end();
            errdefer |err| transaction.fail(@errorName(err));
            return error.DebzFailed;
        }
    };
    try std.testing.expectError(error.DebzFailed, FailureHarness.run(&recorder));
    try recorder.write(.failure);
    const json = try Dir.cwd().readFileAlloc(
        io,
        output_path,
        std.testing.allocator,
        .limited(64 * 1024),
    );
    defer std.testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "debz_transaction",
        parsed.value.object.get("failed_phase").?.string,
    );
    try std.testing.expectEqualStrings(
        "linux-azure",
        parsed.value.object.get("failed_item").?.string,
    );
    try std.testing.expectEqualStrings(
        "DebzFailed",
        parsed.value.object.get("error_name").?.string,
    );

    const missing_parent = "test-image-phase-timing-missing";
    Dir.cwd().deleteTree(io, missing_parent) catch {};
    var unwritable = Recorder.init(
        std.testing.allocator,
        io,
        missing_parent ++ "/timing.json",
    );
    unwritable.append(.{
        .phase = .total_runtime,
        .item = null,
        .elapsed_ns = 1,
        .outcome = .failure,
        .error_name = "BuildFailed",
    });
    try std.testing.expectError(error.FileNotFound, unwritable.write(.failure));
}
