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

test "a command provided through update-alternatives satisfies the contract" {
    // Ubuntu 26.04 ships `/usr/bin/sudo` as a link into `/etc/alternatives`,
    // which is how Debian provides a command at all. The built-root check has
    // to follow that chain, or the contract would refuse the very package it
    // asked for. What it must not do is accept a chain that ends nowhere, ends
    // in a directory, or loops.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tree = try Tree.init(allocator, io, "alternatives");
    defer tree.deinit();
    try populateSatisfyingRoot(&tree);

    var host: HostRoot = .{ .tree = &tree };
    var diagnostic: runtime_contract.Diagnostic = .{};

    try tree.remove("/usr/bin/sudo");
    try tree.writeFile("/usr/bin/sudo.ws", "#!/bin/sh\n");
    try tree.symlink("/etc/alternatives/sudo", "/usr/bin/sudo.ws");
    try tree.symlink("/usr/bin/sudo", "/etc/alternatives/sudo");
    try runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic);

    // A relative alternative resolves against the link's own directory.
    try tree.remove("/etc/alternatives/sudo");
    try tree.symlink("/etc/alternatives/sudo", "../../usr/bin/sudo.ws");
    try runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic);

    // A chain that ends nowhere is the command being missing.
    try tree.remove("/usr/bin/sudo.ws");
    diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), "/usr/bin/sudo") != null,
    );

    // A chain that loops must fail rather than run forever.
    try tree.remove("/etc/alternatives/sudo");
    try tree.symlink("/etc/alternatives/sudo", "/usr/bin/sudo");
    diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyRoot(allocator, host.probe(), &diagnostic),
    );
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

/// A shipped package lock for a guest built the way #677 step 4 builds one:
/// the literal `guest_runtime` roots plus a selected versioned kernel image and
/// its module tree, and nothing the build alone needed.
fn guestLock(allocator: Allocator, extra: []const []const u8) ![]u8 {
    var lock: std.ArrayList(u8) = .empty;
    errdefer lock.deinit(allocator);
    for (contract.requirements()) |requirement| {
        if (requirement.kind != .package or requirement.audience != .guest_runtime) continue;
        try lock.print(allocator, "{s}\t1.0-1\tamd64\n", .{requirement.target});
    }
    try lock.appendSlice(allocator, "linux-image-7.0.0-1010-azure\t7.0.0-1010.10\tamd64\n");
    try lock.appendSlice(allocator, "linux-modules-7.0.0-1010-azure\t7.0.0-1010.10\tamd64\n");
    for (extra) |name| try lock.print(allocator, "{s}\t1.0-1\tamd64\n", .{name});
    return lock.toOwnedSlice(allocator);
}

test "the shipped package lock must contain every contract package" {
    var diagnostic: runtime_contract.Diagnostic = .{};
    const allocator = std.testing.allocator;

    const complete = try guestLock(allocator, &.{"unrelated"});
    defer allocator.free(complete);
    try runtime_contract.verifyPackages(complete, &diagnostic);

    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);
    for (contract.requirements()) |requirement| {
        if (requirement.kind != .package or requirement.audience != .guest_runtime) continue;
        if (std.mem.eql(u8, requirement.target, "ca-certificates")) continue;
        try missing.print(allocator, "{s}\t1.0-1\tamd64\n", .{requirement.target});
    }
    try missing.appendSlice(allocator, "linux-image-7.0.0-1010-azure\t7.0.0-1010.10\tamd64\n");
    try missing.appendSlice(allocator, "linux-modules-7.0.0-1010-azure\t7.0.0-1010.10\tamd64\n");
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

test "build-only packages cannot enter the final guest inventory" {
    // Issue #677 step 4: the initramfs generator is resolved into a staging
    // root that is discarded. If it is present in the shipped lock the
    // separation leaked, and the build that produced the image fails.
    const allocator = std.testing.allocator;
    var diagnostic: runtime_contract.Diagnostic = .{};

    const clean = try guestLock(allocator, &.{});
    defer allocator.free(clean);
    try runtime_contract.verifyPackages(clean, &diagnostic);

    try std.testing.expect(contract.build_package_roots.len != 0);
    for (contract.build_package_roots) |build_root| {
        const polluted = try guestLock(allocator, &.{build_root});
        defer allocator.free(polluted);
        diagnostic = .{};
        try std.testing.expectError(
            error.Failed,
            runtime_contract.verifyPackages(polluted, &diagnostic),
        );
        try std.testing.expect(
            std.mem.indexOf(u8, diagnostic.message(), build_root) != null,
        );
    }
}

test "the shipped lock must select exactly one kernel and not its metapackage" {
    const allocator = std.testing.allocator;
    var diagnostic: runtime_contract.Diagnostic = .{};

    const selected = try guestLock(allocator, &.{});
    defer allocator.free(selected);
    const release_name = try runtime_contract.verifyKernelSelection(selected, &diagnostic);
    try std.testing.expectEqualStrings("7.0.0-1010-azure", release_name);

    // The convenience metapackage is what drags headers, perf tools, cloud
    // tools, and a ZFS module set into an appliance that boots one kernel.
    const with_metapackage = try guestLock(allocator, &.{contract.kernel_templates.selector});
    defer allocator.free(with_metapackage);
    diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyKernelSelection(with_metapackage, &diagnostic),
    );

    // Two kernels make "the kernel the UKI was built from" ambiguous.
    const two_kernels = try guestLock(allocator, &.{"linux-image-7.0.0-1004-azure"});
    defer allocator.free(two_kernels);
    diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyKernelSelection(two_kernels, &diagnostic),
    );

    // An image with no module tree boots into a machine with no drivers.
    var image_only: std.ArrayList(u8) = .empty;
    defer image_only.deinit(allocator);
    try image_only.appendSlice(allocator, "linux-image-7.0.0-1010-azure\t7.0.0-1010.10\tamd64\n");
    diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        runtime_contract.verifyKernelSelection(image_only.items, &diagnostic),
    );
}

test "the shipped package lock must contain no package the contract forbids" {
    // Issue #677 step 3: `ubuntu-minimal` and the conveniences it used to drag
    // in fail the lock by name, so a regression is attributable rather than an
    // anonymous count mismatch.
    var diagnostic: runtime_contract.Diagnostic = .{};
    const allocator = std.testing.allocator;

    const complete = try guestLock(allocator, &.{});
    defer allocator.free(complete);
    try runtime_contract.verifyPackages(complete, &diagnostic);

    for (contract.forbidden_packages) |forbidden| {
        const polluted = try guestLock(allocator, &.{forbidden});
        defer allocator.free(polluted);
        diagnostic = .{};
        try std.testing.expectError(
            error.Failed,
            runtime_contract.verifyPackages(polluted, &diagnostic),
        );
        try std.testing.expect(
            std.mem.indexOf(u8, diagnostic.message(), forbidden) != null,
        );
    }
    try std.testing.expect(contract.isForbiddenPackage("ubuntu-minimal"));
    try std.testing.expect(!contract.isForbiddenPackage("ca-certificates"));
}

test "the published contract carries the explicit roots and the forbidden set" {
    const allocator = std.testing.allocator;
    var subject = try Tree.init(allocator, std.testing.io, "published-closure");
    defer subject.deinit();
    const path = try subject.path("contract.json");
    defer allocator.free(path);
    var diagnostic: runtime_contract.Diagnostic = .{};
    try runtime_contract.write(allocator, std.testing.io, path, "x86_64", "core", &diagnostic);

    var parsed = try runtime_contract.readValidated(
        allocator,
        std.testing.io,
        path,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    );
    defer parsed.deinit();
    const object = parsed.value.object;
    const roots = object.get("package_roots").?.array.items;
    try std.testing.expectEqual(contract.package_roots.len, roots.len);
    var saw_ca_certificates = false;
    for (roots, contract.package_roots) |published, expected| {
        try std.testing.expectEqualStrings(expected, published.string);
        try std.testing.expect(!std.mem.eql(u8, published.string, "ubuntu-minimal"));
        if (std.mem.eql(u8, published.string, "ca-certificates")) saw_ca_certificates = true;
    }
    try std.testing.expect(saw_ca_certificates);
    const forbidden = object.get("forbidden_packages").?.array.items;
    try std.testing.expectEqual(contract.forbidden_packages.len, forbidden.len);
    var saw_ubuntu_minimal = false;
    for (forbidden) |published| {
        if (std.mem.eql(u8, published.string, "ubuntu-minimal")) saw_ubuntu_minimal = true;
    }
    try std.testing.expect(saw_ubuntu_minimal);

    // Issue #677 step 4: the published contract says where each root is
    // resolved and how the kernel is chosen, so a reader does not have to
    // infer either from the closure.
    const guest_roots = object.get("guest_package_roots").?.array.items;
    try std.testing.expectEqual(contract.guest_package_roots.len, guest_roots.len);
    for (guest_roots) |published| {
        try std.testing.expect(!std.mem.eql(u8, published.string, "initramfs-tools"));
    }
    const build_roots = object.get("build_package_roots").?.array.items;
    try std.testing.expectEqual(contract.build_package_roots.len, build_roots.len);
    try std.testing.expectEqualStrings("initramfs-tools", build_roots[0].string);
    const selector = object.get("kernel_selector").?.object;
    try std.testing.expectEqualStrings("linux-azure", selector.get("selector").?.string);
    try std.testing.expectEqualStrings(
        "linux-image-*-azure",
        selector.get("image_template").?.string,
    );
    try std.testing.expectEqualStrings(
        "linux-modules-*-azure",
        selector.get("modules_template").?.string,
    );

    // A candidate that quietly drops an exclusion is refused, and so is one
    // that adds a root the contract does not name.
    const text = try Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(text);
    for ([_][]const u8{ "\"ubuntu-minimal\"", "\"ca-certificates\"" }) |needle| {
        const edited = try std.mem.replaceOwned(u8, allocator, text, needle, "\"convenient\"");
        defer allocator.free(edited);
        try Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = edited });
        diagnostic = .{};
        try std.testing.expectError(error.Failed, runtime_contract.readValidated(
            allocator,
            std.testing.io,
            path,
            .{ .architecture = "x86_64", .flavor = "core" },
            &diagnostic,
        ));
    }
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
