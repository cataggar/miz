//! Behavioral coverage of the Ubuntu 26.04 core runtime contract.
//!
//! `scripts/ubuntu2604/runtime_contract.zig` owns the table's own invariants.
//! This file covers what happens when the contract meets something real: a
//! written provenance document, a built root that satisfies or violates it, a
//! shipped package lock, a guest probe report, and the ext4 accounting the
//! size inventory's `first_boot` phase is assembled from.
//!
//! Every failure path is exercised with a real message, because a gate whose
//! rejection text nobody has read is a gate that will be read for the first
//! time during an incident.

const std = @import("std");

const release = @import("ubuntu2604_release");
const contract = @import("ubuntu2604_runtime_contract");

const runtime_contract = release.runtime_contract_document;
const size_inventory = release.size_inventory;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

/// A throwaway directory tree, used both as a fake "built root" and as a place
/// to write documents.
const Tree = struct {
    allocator: Allocator,
    io: Io,
    root: []u8,

    fn init(allocator: Allocator, io: Io, name: []const u8) !Tree {
        const root = try std.fmt.allocPrint(allocator, ".scratch/runtime-contract/{s}", .{name});
        errdefer allocator.free(root);
        Dir.cwd().deleteTree(io, root) catch {};
        try Dir.cwd().createDirPath(io, root);
        return .{ .allocator = allocator, .io = io, .root = root };
    }

    fn deinit(self: *Tree) void {
        Dir.cwd().deleteTree(self.io, self.root) catch {};
        self.allocator.free(self.root);
        self.* = undefined;
    }

    fn path(self: *const Tree, relative: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.root, relative });
    }

    fn writeFile(self: *const Tree, relative: []const u8, data: []const u8) !void {
        const target = try self.path(relative);
        defer self.allocator.free(target);
        if (std.fs.path.dirname(target)) |parent| {
            try Dir.cwd().createDirPath(self.io, parent);
        }
        try Dir.cwd().writeFile(self.io, .{ .sub_path = target, .data = data });
    }

    fn createDir(self: *const Tree, relative: []const u8) !void {
        const target = try self.path(relative);
        defer self.allocator.free(target);
        try Dir.cwd().createDirPath(self.io, target);
    }

    fn symlink(self: *const Tree, relative: []const u8, target_text: []const u8) !void {
        const link = try self.path(relative);
        defer self.allocator.free(link);
        if (std.fs.path.dirname(link)) |parent| {
            try Dir.cwd().createDirPath(self.io, parent);
        }
        Dir.cwd().deleteTree(self.io, link) catch {};
        try Dir.cwd().symLink(self.io, target_text, link, .{});
    }

    fn remove(self: *const Tree, relative: []const u8) !void {
        const target = try self.path(relative);
        defer self.allocator.free(target);
        Dir.cwd().deleteTree(self.io, target) catch {};
    }
};

/// A `RootProbe` backed by an ordinary host directory, which is how these
/// tests can exercise the same gate the builder runs against ext4.
const HostRoot = struct {
    tree: *const Tree,

    fn stat(context: *anyopaque, path: []const u8) ?runtime_contract.EntryKind {
        const self: *HostRoot = @ptrCast(@alignCast(context));
        const joined = self.join(path) orelse return null;
        defer self.tree.allocator.free(joined);
        const info = Dir.cwd().statFile(self.tree.io, joined, .{
            .follow_symlinks = false,
        }) catch return null;
        return switch (info.kind) {
            .file => .regular,
            .directory => .directory,
            .sym_link => .symlink,
            else => .other,
        };
    }

    fn readLink(context: *anyopaque, path: []const u8, out: []u8) ?[]const u8 {
        const self: *HostRoot = @ptrCast(@alignCast(context));
        const joined = self.join(path) orelse return null;
        defer self.tree.allocator.free(joined);
        const length = Dir.cwd().readLink(self.tree.io, joined, out) catch return null;
        return out[0..length];
    }

    fn read(context: *anyopaque, path: []const u8, out: []u8) ?[]const u8 {
        const self: *HostRoot = @ptrCast(@alignCast(context));
        const joined = self.join(path) orelse return null;
        defer self.tree.allocator.free(joined);
        const bytes = Dir.cwd().readFileAlloc(
            self.tree.io,
            joined,
            self.tree.allocator,
            .limited(out.len),
        ) catch return null;
        defer self.tree.allocator.free(bytes);
        @memcpy(out[0..bytes.len], bytes);
        return out[0..bytes.len];
    }

    fn join(self: *const HostRoot, path: []const u8) ?[]u8 {
        const relative = std.mem.trimStart(u8, path, "/");
        return std.fs.path.join(
            self.tree.allocator,
            &.{ self.tree.root, relative },
        ) catch null;
    }

    fn probe(self: *HostRoot) runtime_contract.RootProbe {
        return .{
            .context = @ptrCast(self),
            .statFn = stat,
            .readLinkFn = readLink,
            .readFn = read,
        };
    }
};

/// Materializes exactly the entries a built root is contractually required to
/// carry, and nothing else, so a test that removes one is removing the only
/// reason the check would pass.
fn populateSatisfyingRoot(tree: *const Tree) !void {
    for (contract.requirements()) |requirement| {
        if (!runtime_contract.checkedInRoot(requirement)) continue;
        switch (requirement.kind) {
            .command, .file => try tree.writeFile(requirement.target, "payload"),
            .directory => try tree.createDir(requirement.target),
            .symlink => try tree.symlink(requirement.target, requirement.expect),
            .config, .trust_store => {
                const contents = try std.fmt.allocPrint(
                    tree.allocator,
                    "preamble\n{s}\ntrailer\n",
                    .{requirement.expect},
                );
                defer tree.allocator.free(contents);
                try tree.writeFile(requirement.target, contents);
            },
            else => unreachable,
        }
    }
}

fn firstCheckedRoot(kind: contract.Kind) contract.Requirement {
    for (contract.requirements()) |requirement| {
        if (runtime_contract.checkedInRoot(requirement) and requirement.kind == kind) {
            return requirement;
        }
    }
    unreachable;
}

test "a written runtime contract document validates against the compiled contract" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "document");
    defer tree.deinit();

    const filename = try runtime_contract.filenameAlloc(allocator, "core", "x86_64");
    defer allocator.free(filename);
    try std.testing.expectEqualStrings(
        "ubuntu2604-runtime-contract-core-x86_64.json",
        filename,
    );

    const path = try tree.path(filename);
    defer allocator.free(path);
    var diagnostic: runtime_contract.Diagnostic = .{};
    try runtime_contract.write(allocator, io, path, "x86_64", "core", &diagnostic);

    var parsed = try runtime_contract.readValidated(allocator, io, path, .{
        .architecture = "x86_64",
        .flavor = "core",
    }, &diagnostic);
    defer parsed.deinit();
    const summary = try runtime_contract.validateDocument(parsed.value, .{}, &diagnostic);
    try std.testing.expectEqualStrings("x86_64", summary.architecture);
    try std.testing.expectEqualStrings("core", summary.flavor);
    try std.testing.expectEqual(contract.requirements().len, summary.total);
    try std.testing.expectEqual(
        contract.countFor(.guest_runtime),
        summary.guest_runtime,
    );
    try std.testing.expect(summary.acceptance_only != 0);
    const expected_digest = contract.digest();
    try std.testing.expectEqualStrings(&expected_digest, summary.contract_sha256);
}

test "the two architectures produce identical contracts under different identities" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "architectures");
    defer tree.deinit();
    var diagnostic: runtime_contract.Diagnostic = .{};

    for ([_][]const u8{ "x86_64", "aarch64" }) |architecture| {
        const filename = try runtime_contract.filenameAlloc(allocator, "core", architecture);
        defer allocator.free(filename);
        const path = try tree.path(filename);
        defer allocator.free(path);
        try runtime_contract.write(allocator, io, path, architecture, "core", &diagnostic);
        var parsed = try runtime_contract.readValidated(allocator, io, path, .{
            .architecture = architecture,
            .flavor = "core",
        }, &diagnostic);
        defer parsed.deinit();

        // Asking for the other architecture must be refused by name: the
        // document is per-candidate provenance, not a shared file.
        const other = if (std.mem.eql(u8, architecture, "x86_64")) "aarch64" else "x86_64";
        try std.testing.expectError(error.Failed, runtime_contract.validateDocument(
            parsed.value,
            .{ .architecture = other },
            &diagnostic,
        ));
        try std.testing.expect(
            std.mem.indexOf(u8, diagnostic.message(), other) != null,
        );
        try std.testing.expectError(error.Failed, runtime_contract.validateDocument(
            parsed.value,
            .{ .flavor = "full" },
            &diagnostic,
        ));
    }
}

test "a document whose requirements were edited is refused by requirement name" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "tampered");
    defer tree.deinit();
    var diagnostic: runtime_contract.Diagnostic = .{};

    const path = try tree.path("contract.json");
    defer allocator.free(path);
    try runtime_contract.write(allocator, io, path, "aarch64", "core", &diagnostic);
    const text = try Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(text);

    const tampered = try std.mem.replaceOwned(
        u8,
        allocator,
        text,
        "\"target\": \"/usr/bin/sudo\"",
        "\"target\": \"/usr/local/bin/sudo\"",
    );
    defer allocator.free(tampered);
    try std.testing.expect(!std.mem.eql(u8, text, tampered));
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, tampered, .{});
    defer parsed.deinit();
    try std.testing.expectError(
        error.Failed,
        runtime_contract.validateDocument(parsed.value, .{}, &diagnostic),
    );
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "sudo") != null);

    // A dropped requirement is refused by count rather than silently accepted.
    const shortened = try std.mem.replaceOwned(
        u8,
        allocator,
        text,
        "\"id\": \"mizinit\",",
        "\"id\": \"mizinit-renamed\",",
    );
    defer allocator.free(shortened);
    var renamed = try std.json.parseFromSlice(std.json.Value, allocator, shortened, .{});
    defer renamed.deinit();
    try std.testing.expectError(
        error.Failed,
        runtime_contract.validateDocument(renamed.value, .{}, &diagnostic),
    );
}

/// Whether any other checked requirement lives inside `requirement`'s target,
/// which makes removing it a cascading removal rather than an isolated one.
fn containsAnotherRequirement(requirement: contract.Requirement) bool {
    for (contract.requirements()) |other| {
        if (!runtime_contract.checkedInRoot(other)) continue;
        if (std.mem.eql(u8, other.id, requirement.id)) continue;
        if (other.target.len > requirement.target.len and
            std.mem.startsWith(u8, other.target, requirement.target) and
            other.target[requirement.target.len] == '/') return true;
    }
    return false;
}

test "a built root that satisfies the contract passes and every omission fails by name" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "root");
    defer tree.deinit();
    try populateSatisfyingRoot(&tree);

    var host: HostRoot = .{ .tree = &tree };
    var diagnostic: runtime_contract.Diagnostic = .{};
    try runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic);

    var checked: usize = 0;
    for (contract.requirements()) |requirement| {
        if (!runtime_contract.checkedInRoot(requirement)) continue;
        checked += 1;
        try tree.remove(requirement.target);
        try std.testing.expectError(
            error.Failed,
            runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
        );
        // A directory that holds other required entries takes them with it, so
        // only an isolated removal can be asserted to name its own identifier.
        if (!containsAnotherRequirement(requirement)) {
            try std.testing.expect(
                std.mem.indexOf(u8, diagnostic.message(), requirement.id) != null,
            );
            try std.testing.expect(
                std.mem.indexOf(u8, diagnostic.message(), requirement.target) != null,
            );
        }
        try populateSatisfyingRoot(&tree);
        try runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic);
    }
    try std.testing.expect(checked >= 10);
}

test "a trust store without a certificate marker is a broken trust store" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "trust-store");
    defer tree.deinit();
    try populateSatisfyingRoot(&tree);

    var host: HostRoot = .{ .tree = &tree };
    var diagnostic: runtime_contract.Diagnostic = .{};
    const bundle = contract.lookup("ca-certificates-bundle").?;
    try tree.writeFile(bundle.target, "");
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "ca-certificates-bundle") != null,
    );

    try tree.writeFile(bundle.target, "-----BEGIN NOT A CERTIFICATE-----\n");
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
}

test "a symbolic link pointing somewhere else is refused with both targets named" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "symlink");
    defer tree.deinit();
    try populateSatisfyingRoot(&tree);

    var host: HostRoot = .{ .tree = &tree };
    var diagnostic: runtime_contract.Diagnostic = .{};
    const link = firstCheckedRoot(.symlink);
    try tree.remove(link.target);
    try tree.symlink(link.target, "systemd");
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "systemd") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), link.expect) != null);

    // A regular file where a link belongs is a different failure with the same
    // consequence, and must not be mistaken for a satisfied requirement.
    try tree.remove(link.target);
    try tree.writeFile(link.target, "not a link");
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "symbolic link") != null,
    );
}

test "the shipped package lock must contain every contract package" {
    var diagnostic: runtime_contract.Diagnostic = .{};
    const allocator = std.testing.allocator;

    var complete: std.ArrayList(u8) = .empty;
    defer complete.deinit(allocator);
    for (contract.requirements()) |requirement| {
        if (requirement.kind != .package) continue;
        try complete.print(allocator, "{s}\t1.0-1\tamd64\n", .{requirement.target});
    }
    try complete.appendSlice(allocator, "unrelated\t2.0\tamd64\n");
    try runtime_contract.verifyPackages(complete.items, &diagnostic);

    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);
    for (contract.requirements()) |requirement| {
        if (requirement.kind != .package) continue;
        if (std.mem.eql(u8, requirement.target, "ca-certificates")) continue;
        try missing.print(allocator, "{s}\t1.0-1\tamd64\n", .{requirement.target});
    }
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyPackages(missing.items, &diagnostic),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "ca-certificates") != null,
    );

    // A package name must match a whole lock field: a longer name that merely
    // starts with it is a different package.
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyPackages("ca-certificates-java\t1.0\tamd64\n", &diagnostic),
    );
}

fn probeReportAlloc(allocator: Allocator, failing: ?[]const u8) ![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    for (contract.requirements()) |requirement| {
        if (!requirement.kind.probeable()) continue;
        const status: contract.Status = if (failing) |id|
            (if (std.mem.eql(u8, id, requirement.id)) .missing else .ok)
        else
            .ok;
        try text.print(allocator, "{s} id={s} kind={s} audience={s} status={s} target={s}\n", .{
            contract.report_prefix,
            requirement.id,
            requirement.kind.key(),
            requirement.audience.key(),
            status.key(),
            requirement.target,
        });
    }
    return text.toOwnedSlice(allocator);
}

test "a guest probe report is accepted whole and refused by requirement" {
    const allocator = std.testing.allocator;
    var diagnostic: runtime_contract.Diagnostic = .{};

    const complete = try probeReportAlloc(allocator, null);
    defer allocator.free(complete);
    try runtime_contract.verifyProbeReport(complete, &diagnostic);

    const broken = try probeReportAlloc(allocator, "binderfs-mount");
    defer allocator.free(broken);
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyProbeReport(broken, &diagnostic),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "binderfs-mount") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "/dev/binderfs") != null,
    );

    // An acceptance-only convenience that is gone does not fail the guest:
    // nothing in the image may be retained solely for a test.
    const harness_absent = try probeReportAlloc(allocator, "harness-od");
    defer allocator.free(harness_absent);
    try runtime_contract.verifyProbeReport(harness_absent, &diagnostic);

    // Truncated output is refused rather than treated as a pass.
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyProbeReport("", &diagnostic),
    );
}

test "probe filesystem accounting feeds the size inventory first-boot phase" {
    const allocator = std.testing.allocator;
    var diagnostic: runtime_contract.Diagnostic = .{};
    const output =
        "runtime-contract id=mizinit status=ok target=/usr/sbin/mizinit\n" ++
        "filesystem path=/mnt block_size=4096 total_blocks=100 free_blocks=10 " ++
        "total_inodes=64 free_inodes=32\n" ++
        "filesystem path=/ block_size=4096 total_blocks=917504 free_blocks=180000 " ++
        "total_inodes=229376 free_inodes=200000\n";
    const usage = try runtime_contract.filesystemUsage(output, "/", &diagnostic);
    try std.testing.expectEqual(@as(u64, 917504), usage.total_blocks);
    try std.testing.expectEqual(@as(u64, 200000), usage.free_inodes);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    var inventory_diagnostic: size_inventory.Diagnostic = .{};
    const section = try size_inventory.firstBootValue(arena.allocator(), .{
        .block_size = usage.block_size,
        .total_blocks = usage.total_blocks,
        .free_blocks = usage.free_blocks,
        .total_inodes = usage.total_inodes,
        .free_inodes = usage.free_inodes,
    }, &inventory_diagnostic);
    try std.testing.expectEqual(
        @as(i64, 917504 - 180000),
        section.object.get("root_used_blocks").?.integer,
    );

    try std.testing.expectError(
        error.Failed,
        runtime_contract.filesystemUsage(output, "/srv", &diagnostic),
    );
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "/srv") != null);

    // Accounting that does not add up is a broken measurement, not a small one.
    try std.testing.expectError(error.Failed, runtime_contract.filesystemUsage(
        "filesystem path=/ block_size=4096 total_blocks=10 free_blocks=20 " ++
            "total_inodes=5 free_inodes=1\n",
        "/",
        &diagnostic,
    ));
}
