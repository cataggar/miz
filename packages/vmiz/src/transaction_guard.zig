const std = @import("std");

const Io = std.Io;

pub const active_lease_basename = ".vmiz-active-backend";
pub const lock_suffix = ".backend.lock";
pub const sealed_suffix = ".backend-sealed";

pub fn activeLeasePath(
    transaction_path: []const u8,
    buffer: *[Io.Dir.max_path_bytes]u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "{s}/{s}",
        .{ transaction_path, active_lease_basename },
    );
}

pub fn hasActiveLease(io: Io, transaction_path: []const u8) !bool {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try activeLeasePath(transaction_path, &buffer);
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

pub const Lease = struct {
    lock_file: Io.File,
    transaction_path: []const u8,
    active: bool = true,

    pub fn release(self: *Lease, io: Io) !void {
        if (!self.active) return;
        var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = try activeLeasePath(self.transaction_path, &buffer);
        const delete_result = Io.Dir.cwd().deleteFile(io, path);
        self.lock_file.close(io);
        self.active = false;
        try delete_result;
    }

    /// Drops the process lock but intentionally leaves the active marker so
    /// publication and recursive cleanup remain blocked for manual recovery.
    pub fn abandon(self: *Lease, io: Io) void {
        if (!self.active) return;
        self.lock_file.close(io);
        self.active = false;
    }
};

pub const CommitBarrier = struct {
    lock_file: Io.File,
    active: bool = true,

    pub fn release(self: *CommitBarrier, io: Io) void {
        if (!self.active) return;
        self.lock_file.close(io);
        self.active = false;
    }
};

pub fn acquire(io: Io, transaction_path: []const u8) !Lease {
    const lock_file = try openLock(io, transaction_path);
    errdefer lock_file.close(io);
    if (try isSealed(io, transaction_path)) return error.TransactionSealed;
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try activeLeasePath(transaction_path, &buffer);
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
    });
    file.close(io);
    return .{
        .lock_file = lock_file,
        .transaction_path = transaction_path,
    };
}

pub fn seal(io: Io, transaction_path: []const u8) !CommitBarrier {
    const lock_file = try openLock(io, transaction_path);
    errdefer lock_file.close(io);
    if (try hasActiveLease(io, transaction_path)) return error.ActiveBackendLease;
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try statePath(transaction_path, sealed_suffix, &buffer);
    const sealed = Io.Dir.cwd().createFile(io, path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => null,
        else => return err,
    };
    if (sealed) |file| file.close(io);
    return .{ .lock_file = lock_file };
}

fn openLock(io: Io, transaction_path: []const u8) !Io.File {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try statePath(transaction_path, lock_suffix, &buffer);
    return Io.Dir.cwd().createFile(io, path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });
}

fn isSealed(io: Io, transaction_path: []const u8) !bool {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try statePath(transaction_path, sealed_suffix, &buffer);
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// Removes the out-of-tree seal only after the sealed transaction directory
/// has been deleted. Until then, no new backend lease can enter the path.
pub fn finishCleanup(io: Io, transaction_path: []const u8) !void {
    var sealed_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const sealed_path = try statePath(
        transaction_path,
        sealed_suffix,
        &sealed_buffer,
    );
    try Io.Dir.cwd().deleteFile(io, sealed_path);
    var lock_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const lock_path = try statePath(transaction_path, lock_suffix, &lock_buffer);
    try Io.Dir.cwd().deleteFile(io, lock_path);
}

fn childPath(
    transaction_path: []const u8,
    basename: []const u8,
    buffer: *[Io.Dir.max_path_bytes]u8,
) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ transaction_path, basename });
}

fn statePath(
    transaction_path: []const u8,
    suffix: []const u8,
    buffer: *[Io.Dir.max_path_bytes]u8,
) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ transaction_path, suffix });
}

test "lease release permits sealing while abandonment retains recovery marker" {
    const io = std.testing.io;
    const transaction_path = "test-transaction-guard";
    defer Io.Dir.cwd().deleteTree(io, transaction_path) catch {};
    var lock_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const lock_path = try statePath(
        transaction_path,
        lock_suffix,
        &lock_buffer,
    );
    defer Io.Dir.cwd().deleteFile(io, lock_path) catch {};
    var sealed_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const sealed_path = try statePath(
        transaction_path,
        sealed_suffix,
        &sealed_buffer,
    );
    defer Io.Dir.cwd().deleteFile(io, sealed_path) catch {};

    try Io.Dir.cwd().createDir(io, transaction_path, .default_dir);
    var released = try acquire(io, transaction_path);
    try std.testing.expect(try hasActiveLease(io, transaction_path));
    try released.release(io);
    try std.testing.expect(!try hasActiveLease(io, transaction_path));
    var barrier = try seal(io, transaction_path);
    barrier.release(io);
    try Io.Dir.cwd().deleteTree(io, transaction_path);
    try finishCleanup(io, transaction_path);

    try Io.Dir.cwd().createDir(io, transaction_path, .default_dir);
    var abandoned = try acquire(io, transaction_path);
    abandoned.abandon(io);
    try std.testing.expect(try hasActiveLease(io, transaction_path));
    try std.testing.expectError(
        error.ActiveBackendLease,
        seal(io, transaction_path),
    );
}
