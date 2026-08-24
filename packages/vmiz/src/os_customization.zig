const std = @import("std");
const ext4 = @import("ext4.zig");
const root_tree = @import("root_tree.zig");

const Allocator = std.mem.Allocator;
const RootTree = root_tree.RootTree;

pub const Metadata = struct {
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    /// The modification time to stamp on the node, or null to take the
    /// build's own deterministic default.
    ///
    /// A caller writing a file into an image is stating what that file is,
    /// and its mtime is part of that statement: it is what every package
    /// manager, `make`, `find -newer` and staleness check in the guest will
    /// read. Left to the default, an injected file claims to have been
    /// modified at the moment the image was built, which is a plausible
    /// lie -- it says the bytes are as new as the image, when the caller may
    /// be reproducing a file that has a real age, or deliberately backdating
    /// one so a guest-side generator considers its output current.
    ///
    /// Only mtime is exposed. atime is meaningless in an image nothing has
    /// read yet, and ctime is inode-change time, which no tool on a running
    /// system can set and which therefore has no value a caller could
    /// intend. Both continue to take the build default.
    mtime: ?i64 = null,
    xattrs: []const ext4.Xattr = &.{},

    fn rootTree(self: Metadata) root_tree.Metadata {
        return .{
            .mode = self.mode,
            .uid = self.uid,
            .gid = self.gid,
            .mtime = self.mtime,
            .xattrs = self.xattrs,
        };
    }
};

pub const FileSource = union(enum) {
    inline_bytes: []const u8,
    host_path: []const u8,
};

pub const PutFile = struct {
    path: []const u8,
    source: FileSource,
    metadata: Metadata = .{ .mode = 0o644 },
};

pub const PutDirectory = struct {
    path: []const u8,
    metadata: Metadata = .{ .mode = 0o755 },
};

pub const PutSymlink = struct {
    path: []const u8,
    target: []const u8,
    metadata: Metadata = .{ .mode = 0o777 },
};

pub const MetadataChange = struct {
    path: []const u8,
    mode: ?u16 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    /// See `Metadata.mtime`. Null keeps the node's existing modification
    /// time, the way the other null fields here keep theirs.
    mtime: ?i64 = null,
    xattrs: ?[]const ext4.Xattr = null,
};

pub const FilesystemOperation = union(enum) {
    put_file: PutFile,
    put_directory: PutDirectory,
    put_symlink: PutSymlink,
    remove: []const u8,
    set_metadata: MetadataChange,
};

pub const Password = union(enum) {
    locked,
    prehashed: []const u8,
};

pub const Group = struct {
    name: []const u8,
    gid: ?u32 = null,
    members: []const []const u8 = &.{},
};

pub const User = struct {
    name: []const u8,
    uid: ?u32 = null,
    gid: ?u32 = null,
    primary_group: ?[]const u8 = null,
    secondary_groups: []const []const u8 = &.{},
    home: ?[]const u8 = null,
    shell: []const u8 = "/bin/bash",
    password: Password = .locked,
    ssh_authorized_keys: []const []const u8 = &.{},
    passwordless_sudo: bool = false,
};

pub const ServiceState = enum {
    enabled,
    disabled,
};

pub const Service = struct {
    name: []const u8,
    state: ServiceState,
};

pub const KernelModule = struct {
    name: []const u8,
    load: bool = false,
    disabled: bool = false,
    options: ?[]const u8 = null,
};

pub const OsCustomization = struct {
    filesystem: []const FilesystemOperation = &.{},
    hostname: ?[]const u8 = null,
    groups: []const Group = &.{},
    users: []const User = &.{},
    services: []const Service = &.{},
    kernel_modules: []const KernelModule = &.{},
};

pub const AzureGeneralization = struct {
    reset_hostname: bool = true,
    clear_machine_id: bool = true,
    remove_ssh_host_keys: bool = true,
    remove_agent_state: bool = true,
    remove_dhcp_leases: bool = true,
    /// Removes `/etc/resolv.conf` when it is a regular file, and leaves it
    /// alone when it is a symlink.
    ///
    /// The distinction is the whole point. A regular file there holds
    /// nameserver addresses, which are machine-specific state in exactly the
    /// way a DHCP lease is -- usually written by the same DHCP client, and
    /// naming the internal DNS topology of wherever the image was last
    /// running. A symlink there is not state at all: it is the target's
    /// resolver wiring, pointing at `/run/systemd/resolve/stub-resolv.conf`
    /// or `/run/NetworkManager/resolv.conf`, both of which are runtime paths
    /// that no published image carries anyway. Deleting the symlink would
    /// remove the configuration and leave the state alone, which is backwards.
    ///
    /// This is a deliberate deviation from `waagent -deprovision`, whose
    /// default handler deletes the path unconditionally. That default is
    /// precisely what upstream's per-distribution handlers exist to override
    /// -- Ubuntu 18.04's, for one, refuses to touch it and says so in a
    /// warning -- so following the default here would be copying the bug
    /// rather than the behaviour.
    remove_resolver_configuration: bool = true,
    remove_logs: bool = false,
    remove_caches: bool = false,
    clear_random_seed: bool = true,
    remove_users: []const []const u8 = &.{},
};

pub const GeneralizationPolicy = union(enum) {
    none,
    azure: AzureGeneralization,
};

pub fn apply(
    allocator: Allocator,
    tree: *RootTree,
    customization: OsCustomization,
    source_date_epoch: u64,
) !void {
    for (customization.filesystem) |operation| try applyFilesystemOperation(tree, operation);
    if (customization.hostname) |hostname| try applyHostname(tree, hostname);
    if (customization.groups.len != 0 or customization.users.len != 0) {
        try applyAccounts(allocator, tree, customization.groups, customization.users, source_date_epoch);
    }
    try applyServices(tree, customization.services);
    try applyKernelModules(allocator, tree, customization.kernel_modules);
}

pub fn generalize(
    allocator: Allocator,
    tree: *RootTree,
    policy: GeneralizationPolicy,
) !void {
    switch (policy) {
        .none => {},
        .azure => |options| {
            try validateUserRemovals(allocator, tree, options.remove_users);
            if (options.reset_hostname) {
                try tree.putFileBytes("etc/hostname", "localhost.localdomain\n", replacementMetadata(tree, "etc/hostname", 0o644));
            }
            if (options.clear_machine_id) {
                try tree.putFileBytes("etc/machine-id", "", replacementMetadata(tree, "etc/machine-id", 0o444));
            }
            if (options.remove_ssh_host_keys) try removeSshHostKeys(tree);
            if (options.remove_agent_state) _ = try tree.remove("var/lib/azagent");
            if (options.remove_dhcp_leases) {
                inline for (.{ "var/lib/dhclient", "var/lib/dhcpcd", "var/lib/dhcp" }) |path| {
                    _ = try tree.remove(path);
                }
            }
            if (options.remove_resolver_configuration) try removeResolverConfiguration(tree);
            if (options.remove_logs) try clearDirectory(tree, "var/log");
            if (options.remove_caches) try clearDirectory(tree, "var/cache");
            if (options.clear_random_seed) {
                if (tree.findNode("var/lib/systemd/random-seed") != null) {
                    try tree.putFileBytes(
                        "var/lib/systemd/random-seed",
                        "",
                        replacementMetadata(tree, "var/lib/systemd/random-seed", 0o600),
                    );
                }
            }
            for (options.remove_users) |username| try removeUser(allocator, tree, username);
        },
    }
}

/// See `AzureGeneralization.remove_resolver_configuration` for why only a
/// regular file is removed.
fn removeResolverConfiguration(tree: *RootTree) !void {
    const node = tree.findNode("etc/resolv.conf") orelse return;
    if (node.kind != .file) return;
    _ = try tree.remove("etc/resolv.conf");
}

fn applyFilesystemOperation(tree: *RootTree, operation: FilesystemOperation) !void {
    switch (operation) {
        .put_file => |file| {
            const path = try normalizedPath(file.path);
            switch (file.source) {
                .inline_bytes => |bytes| try tree.putFileBytes(path, bytes, file.metadata.rootTree()),
                .host_path => |source_path| try tree.putFileFromPath(path, source_path, file.metadata.rootTree()),
            }
        },
        .put_directory => |directory| try tree.putDirectory(
            try normalizedPath(directory.path),
            directory.metadata.rootTree(),
        ),
        .put_symlink => |link| try tree.putSymlink(
            try normalizedPath(link.path),
            link.target,
            link.metadata.rootTree(),
        ),
        .remove => |path| _ = try tree.remove(try normalizedPath(path)),
        .set_metadata => |change| {
            const path = try normalizedPath(change.path);
            const node = tree.findNode(path) orelse return error.MissingCustomizationPath;
            try tree.setMetadata(path, .{
                .mode = change.mode orelse node.metadata.mode,
                .uid = change.uid orelse node.metadata.uid,
                .gid = change.gid orelse node.metadata.gid,
                .atime = node.metadata.atime,
                .mtime = change.mtime orelse node.metadata.mtime,
                .ctime = node.metadata.ctime,
                .xattrs = change.xattrs orelse node.metadata.xattrs,
            });
        },
    }
}

fn applyHostname(tree: *RootTree, hostname: []const u8) !void {
    var content: [65]u8 = undefined;
    const value = try std.fmt.bufPrint(&content, "{s}\n", .{hostname});
    try tree.putFileBytes("etc/hostname", value, replacementMetadata(tree, "etc/hostname", 0o644));
}

/// The `sp_lstchg` field for a newly created account.
///
/// Returns an empty field -- shadow(5)'s "aging disabled" -- rather than the
/// literal 0 that would otherwise mean the password is already expired.
fn formatShadowLastChange(buf: []u8, source_date_epoch: u64) []const u8 {
    const days = source_date_epoch / 86_400;
    if (days == 0) return "";
    return std.fmt.bufPrint(buf, "{d}", .{days}) catch "";
}

fn applyAccounts(
    allocator: Allocator,
    tree: *RootTree,
    groups: []const Group,
    users: []const User,
    source_date_epoch: u64,
) !void {
    var passwd = try readRequiredFile(allocator, tree, "etc/passwd");
    defer allocator.free(passwd);
    var shadow = try readRequiredFile(allocator, tree, "etc/shadow");
    defer allocator.free(shadow);
    var group_file = try readRequiredFile(allocator, tree, "etc/group");
    defer allocator.free(group_file);

    for (groups) |group| {
        if (recordExists(group_file, group.name)) return error.GroupAlreadyExists;
        const gid = group.gid orelse try nextFreeId(group_file, 1000);
        if (idExists(group_file, gid)) return error.GroupIdInUse;
        const members = try joinComma(allocator, group.members);
        defer allocator.free(members);
        group_file = try appendFormatted(
            allocator,
            group_file,
            "{s}:x:{d}:{s}\n",
            .{ group.name, gid, members },
        );
    }

    for (users) |user| {
        if (recordExists(passwd, user.name)) return error.UserAlreadyExists;
        const uid = user.uid orelse try nextFreeUserId(passwd, group_file);
        if (idExists(passwd, uid)) return error.UserIdInUse;
        const primary_name = user.primary_group orelse user.name;
        var gid = user.gid;
        if (findRecordId(group_file, primary_name)) |existing_gid| {
            if (gid != null and gid.? != existing_gid) return error.PrimaryGroupIdMismatch;
            gid = existing_gid;
        } else {
            const new_gid = gid orelse uid;
            if (idExists(group_file, new_gid)) return error.GroupIdInUse;
            group_file = try appendFormatted(
                allocator,
                group_file,
                "{s}:x:{d}:\n",
                .{ primary_name, new_gid },
            );
            gid = new_gid;
        }

        const home = user.home orelse try defaultHomePath(allocator, user.name);
        defer if (user.home == null) allocator.free(home);
        passwd = try appendFormatted(
            allocator,
            passwd,
            "{s}:x:{d}:{d}::{s}:{s}\n",
            .{ user.name, uid, gid.?, home, user.shell },
        );
        const password = switch (user.password) {
            .locked => "!",
            .prehashed => |hash| hash,
        };
        // shadow(5) gives a last-change day of 0 a special meaning: the
        // password must be changed at the next login. For an account whose
        // password is locked and whose only credential is an SSH key that is
        // a lockout with no way back in -- sshd accepts the key and PAM then
        // refuses the session with "password change required but no TTY
        // available". A build with SOURCE_DATE_EPOCH at or below one day lands
        // exactly there. An empty field disables aging instead, which is what
        // a key-only account wants and is just as reproducible.
        var last_change_buf: [24]u8 = undefined;
        const last_change = formatShadowLastChange(&last_change_buf, source_date_epoch);
        shadow = try appendFormatted(
            allocator,
            shadow,
            "{s}:{s}:{s}:0:99999:7:::\n",
            .{ user.name, password, last_change },
        );
        for (user.secondary_groups) |group_name| {
            const updated = try addGroupMember(allocator, group_file, group_name, user.name);
            allocator.free(group_file);
            group_file = updated;
        }

        const home_path = try normalizedPath(home);
        try tree.putDirectory(home_path, .{ .mode = 0o700, .uid = uid, .gid = gid.? });
        if (user.ssh_authorized_keys.len != 0) {
            const ssh_path = try std.fmt.allocPrint(allocator, "{s}/.ssh", .{home_path});
            defer allocator.free(ssh_path);
            const authorized_keys_path = try std.fmt.allocPrint(allocator, "{s}/authorized_keys", .{ssh_path});
            defer allocator.free(authorized_keys_path);
            try tree.putDirectory(ssh_path, .{ .mode = 0o700, .uid = uid, .gid = gid.? });
            const keys = try authorizedKeysContent(allocator, user.ssh_authorized_keys);
            defer allocator.free(keys);
            try tree.putFileBytes(authorized_keys_path, keys, .{ .mode = 0o600, .uid = uid, .gid = gid.? });
        }
        if (user.passwordless_sudo) {
            const sudo_path = try std.fmt.allocPrint(allocator, "etc/sudoers.d/{s}", .{user.name});
            defer allocator.free(sudo_path);
            const sudo_line = try std.fmt.allocPrint(allocator, "{s} ALL=(ALL) NOPASSWD: ALL\n", .{user.name});
            defer allocator.free(sudo_line);
            try tree.putFileBytes(sudo_path, sudo_line, .{ .mode = 0o440 });
        }
    }

    try tree.putFileBytes("etc/passwd", passwd, replacementMetadata(tree, "etc/passwd", 0o644));
    try tree.putFileBytes("etc/shadow", shadow, replacementMetadata(tree, "etc/shadow", 0o600));
    try tree.putFileBytes("etc/group", group_file, replacementMetadata(tree, "etc/group", 0o644));
}

/// Where a system unit can live in an offline root, in the order systemd
/// itself resolves them: an administrator's unit in `/etc` shadows a local
/// one, which shadows the one the distribution's package shipped.
///
/// `/run/systemd/system` is left out on purpose. It is populated by
/// generators at boot and by `systemctl` at runtime, so a unit found there in
/// an image being built would be a leftover from whatever produced the image
/// rather than something the published image will carry.
///
/// `lib/systemd/system` is listed separately from `usr/lib/systemd/system`
/// because a tree is a tree: on a merged-`/usr` image `/lib` is a symlink and
/// the node lookup does not follow it, so a unit shipped at the `lib` path in
/// a non-merged image would otherwise be invisible.
const system_unit_directories = [_][]const u8{
    "etc/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
};

/// Service enablement is modelled as systemd and nothing else, and this is
/// where that assumption is checked rather than assumed.
///
/// Enabling a service here means writing a `.wants` symlink, which is a thing
/// that means something only to systemd. Writing one into an image whose init
/// is anything else produces a file nobody reads, in a directory nobody
/// looks in, and a run that reported success. Every other target assumption
/// in this project refuses what it does not understand -- an unrecognised
/// initramfs generator, bootloader generator or SELinux policy each fail by
/// name -- and this one used to be the exception.
fn findSystemUnitDirectory(tree: *RootTree) ?[]const u8 {
    for (system_unit_directories) |directory| {
        if (tree.findNode(directory)) |node| {
            if (node.kind == .directory) return directory;
        }
    }
    return null;
}

/// The absolute path of the unit fragment `name` resolves to, or null when the
/// target carries no such unit.
///
/// Returned as an absolute path because that is what the symlink has to point
/// at: `systemctl enable` links a `.wants` entry to the fragment's own
/// location, and hard-coding `/usr/lib/systemd/system` meant a unit the caller
/// had just injected into `/etc/systemd/system` -- the obvious way to add one
/// -- was enabled by a symlink into a file that does not exist.
fn resolveSystemUnitPath(
    tree: *RootTree,
    buffer: []u8,
    name: []const u8,
) error{NoSpaceLeft}!?[]const u8 {
    for (system_unit_directories) |directory| {
        const candidate = try std.fmt.bufPrint(buffer, "/{s}/{s}", .{ directory, name });
        // The leading slash belongs to the symlink target, not to the lookup.
        if (tree.findNode(candidate[1..])) |node| {
            if (node.kind != .directory) return candidate;
        }
    }
    return null;
}

pub const ServiceError = error{
    /// The target has no systemd unit directory at all, so there is no
    /// service manager here that a `.wants` symlink would mean anything to.
    UnsupportedServiceManager,
    /// The target is systemd, but carries no unit by that name. Enabling it
    /// would write a symlink pointing at nothing.
    MissingServiceUnit,
};

fn applyServices(tree: *RootTree, services: []const Service) !void {
    if (services.len == 0) return;
    if (findSystemUnitDirectory(tree) == null) return error.UnsupportedServiceManager;

    for (services) |service| {
        var destination_buffer: [512]u8 = undefined;
        const destination = try std.fmt.bufPrint(
            &destination_buffer,
            "etc/systemd/system/multi-user.target.wants/{s}",
            .{service.name},
        );
        switch (service.state) {
            .enabled => {
                var target_buffer: [512]u8 = undefined;
                const target = (try resolveSystemUnitPath(tree, &target_buffer, service.name)) orelse
                    return error.MissingServiceUnit;
                try tree.putSymlink(destination, target, .{ .mode = 0o777 });
            },
            // No unit lookup: disabling is a desired end state, and a target
            // that never had the unit is already in it. What is still checked
            // is the manager, because "disable a service" asked of an image
            // with no service manager is a request nothing can satisfy.
            .disabled => _ = try tree.remove(destination),
        }
    }
}

/// Where kernel-module configuration lands in the target root.
///
/// Closed and named here because three different executors have to agree on
/// it: the rebuild backend writes these into an imported tree, and the
/// `unsafe_chroot` and `vm` backends write them into a real filesystem. A
/// request must produce the same bytes at the same paths whichever one runs.
pub const modules_load_path = "etc/modules-load.d/vmiz.conf";
pub const modprobe_blacklist_path = "etc/modprobe.d/vmiz-blacklist.conf";
pub const modprobe_options_path = "etc/modprobe.d/vmiz-options.conf";

/// The rendered configuration, empty-content entries omitted. Rendering is
/// separated from placing it so a backend that has a mounted filesystem
/// rather than a `RootTree` can use the same bytes.
pub const RenderedFile = struct {
    path: []const u8,
    contents: []const u8,
};

pub fn renderKernelModules(
    allocator: Allocator,
    modules: []const KernelModule,
) ![]const RenderedFile {
    var load: std.Io.Writer.Allocating = .init(allocator);
    defer load.deinit();
    var blacklist: std.Io.Writer.Allocating = .init(allocator);
    defer blacklist.deinit();
    var options: std.Io.Writer.Allocating = .init(allocator);
    defer options.deinit();

    for (modules) |module| {
        if (module.load) try load.writer.print("{s}\n", .{module.name});
        if (module.disabled) try blacklist.writer.print("blacklist {s}\n", .{module.name});
        if (module.options) |value| try options.writer.print("options {s} {s}\n", .{ module.name, value });
    }

    var rendered: std.array_list.Managed(RenderedFile) = .init(allocator);
    errdefer rendered.deinit();
    // A module list that asks for nothing writes nothing, rather than
    // planting empty files the image did not have before.
    inline for (.{
        .{ modules_load_path, &load },
        .{ modprobe_blacklist_path, &blacklist },
        .{ modprobe_options_path, &options },
    }) |entry| {
        if (entry[1].writer.end != 0) {
            try rendered.append(.{
                .path = entry[0],
                .contents = try allocator.dupe(u8, entry[1].written()),
            });
        }
    }
    return rendered.toOwnedSlice();
}

fn applyKernelModules(allocator: Allocator, tree: *RootTree, modules: []const KernelModule) !void {
    const rendered = try renderKernelModules(allocator, modules);
    defer {
        for (rendered) |file| allocator.free(file.contents);
        allocator.free(rendered);
    }
    for (rendered) |file| {
        try tree.putFileBytes(file.path, file.contents, .{ .mode = 0o644 });
    }
}

fn removeSshHostKeys(tree: *RootTree) !void {
    try tree.sortNodes();
    var index = tree.nodeCount();
    while (index != 0) {
        index -= 1;
        const path = tree.nodeView(index).path;
        const basename = std.fs.path.basename(path);
        if (std.mem.startsWith(u8, path, "etc/ssh/") and
            std.mem.startsWith(u8, basename, "ssh_host_") and
            std.mem.indexOf(u8, basename, "_key") != null)
        {
            _ = try tree.remove(path);
        }
    }
}

fn clearDirectory(tree: *RootTree, path: []const u8) !void {
    _ = try tree.remove(path);
    try tree.putDirectory(path, .{ .mode = 0o755 });
}

fn validateUserRemovals(
    allocator: Allocator,
    tree: *const RootTree,
    removed_users: []const []const u8,
) !void {
    if (removed_users.len == 0 or tree.findNode("etc/passwd") == null) return;
    const passwd = try readRequiredFile(allocator, tree, "etc/passwd");
    defer allocator.free(passwd);
    for (removed_users) |username| {
        const home = findUserHome(passwd, username) orelse continue;
        if (std.mem.eql(u8, home, "/")) return error.UnsafeUserHomeRemoval;
        const normalized_home = try normalizedPath(home);
        if (!std.mem.eql(u8, std.fs.path.basename(normalized_home), username)) {
            return error.UnsafeUserHomeRemoval;
        }

        var lines = std.mem.splitScalar(u8, passwd, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.splitScalar(u8, line, ':');
            const retained_name = fields.next() orelse continue;
            if (std.mem.eql(u8, retained_name, username) or stringInList(removed_users, retained_name)) continue;
            _ = fields.next() orelse continue;
            _ = fields.next() orelse continue;
            _ = fields.next() orelse continue;
            _ = fields.next() orelse continue;
            const retained_home = fields.next() orelse continue;
            if (std.mem.eql(u8, retained_home, "/")) continue;
            const normalized_retained = normalizedPath(retained_home) catch return error.UnsafeUserHomeRemoval;
            if (std.mem.eql(u8, normalized_home, normalized_retained) or
                customizationPathContains(normalized_home, normalized_retained) or
                customizationPathContains(normalized_retained, normalized_home))
            {
                return error.SharedUserHome;
            }
        }
    }
}

fn removeUser(allocator: Allocator, tree: *RootTree, username: []const u8) !void {
    var home_path: ?[]u8 = null;
    defer if (home_path) |path| allocator.free(path);
    if (tree.findNode("etc/passwd") != null) {
        const passwd = try readRequiredFile(allocator, tree, "etc/passwd");
        defer allocator.free(passwd);
        if (findUserHome(passwd, username)) |home| {
            if (!std.mem.eql(u8, home, "/")) {
                home_path = try allocator.dupe(u8, try normalizedPath(home));
            }
        }
    }

    for ([_][]const u8{ "etc/passwd", "etc/shadow", "etc/group" }) |path| {
        if (tree.findNode(path) == null) continue;
        const content = try readRequiredFile(allocator, tree, path);
        defer allocator.free(content);
        const filtered = if (std.mem.eql(u8, path, "etc/group"))
            try removeUserFromGroups(allocator, content, username)
        else
            try removeRecord(allocator, content, username);
        defer allocator.free(filtered);
        try tree.putFileBytes(path, filtered, replacementMetadata(tree, path, if (std.mem.eql(u8, path, "etc/shadow")) 0o600 else 0o644));
    }
    if (home_path) |path| _ = try tree.remove(path);
    const sudoers_path = try std.fmt.allocPrint(allocator, "etc/sudoers.d/{s}", .{username});
    defer allocator.free(sudoers_path);
    _ = try tree.remove(sudoers_path);
}

fn normalizedPath(path: []const u8) ![]const u8 {
    if (path.len < 2 or path[0] != '/' or path[1] == '/') return error.InvalidCustomizationPath;
    return path[1..];
}

fn customizationPathContains(parent: []const u8, candidate: []const u8) bool {
    return parent.len < candidate.len and
        std.mem.startsWith(u8, candidate, parent) and
        candidate[parent.len] == '/';
}

fn stringInList(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, needle)) return true;
    }
    return false;
}

fn replacementMetadata(tree: *const RootTree, path: []const u8, default_mode: u16) root_tree.Metadata {
    return if (tree.findNode(path)) |node| node.metadata else .{ .mode = default_mode };
}

fn readRequiredFile(allocator: Allocator, tree: *const RootTree, path: []const u8) ![]u8 {
    return tree.readFileAlloc(allocator, path, 16 * 1024 * 1024);
}

fn recordExists(content: []const u8, name: []const u8) bool {
    return findRecordId(content, name) != null;
}

fn findUserHome(content: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        return fields.next() orelse continue;
    }
    return null;
}

fn findRecordId(content: []const u8, name: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        _ = fields.next() orelse continue;
        return std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch null;
    }
    return null;
}

fn idExists(content: []const u8, id: u32) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const current = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        if (current == id) return true;
    }
    return false;
}

fn nextFreeId(content: []const u8, start: u32) !u32 {
    var candidate = start;
    while (candidate <= 60_000) : (candidate += 1) {
        if (!idExists(content, candidate)) return candidate;
    }
    return error.NoAvailableId;
}

fn nextFreeUserId(passwd: []const u8, groups: []const u8) !u32 {
    var candidate: u32 = 1000;
    while (candidate <= 60_000) : (candidate += 1) {
        if (!idExists(passwd, candidate) and !idExists(groups, candidate)) return candidate;
    }
    return error.NoAvailableId;
}

fn appendFormatted(
    allocator: Allocator,
    previous: []u8,
    comptime format: []const u8,
    args: anytype,
) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, previous.len + 128);
    errdefer output.deinit();
    const trimmed = std.mem.trimEnd(u8, previous, "\n");
    if (trimmed.len != 0) {
        try output.writer.writeAll(trimmed);
        try output.writer.writeByte('\n');
    }
    try output.writer.print(format, args);
    const owned = try output.toOwnedSlice();
    allocator.free(previous);
    return owned;
}

fn joinComma(allocator: Allocator, members: []const []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (members, 0..) |member, index| {
        if (index != 0) try output.writer.writeByte(',');
        try output.writer.writeAll(member);
    }
    return output.toOwnedSlice();
}

fn defaultHomePath(allocator: Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/home/{s}", .{username});
}

fn authorizedKeysContent(allocator: Allocator, keys: []const []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (keys) |key| {
        try output.writer.writeAll(key);
        try output.writer.writeByte('\n');
    }
    return output.toOwnedSlice();
}

fn addGroupMember(allocator: Allocator, content: []const u8, group_name: []const u8, username: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, content.len + username.len + 2);
    errdefer output.deinit();
    var found = false;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first_colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidGroupFile;
        if (!std.mem.eql(u8, line[0..first_colon], group_name)) {
            try output.writer.print("{s}\n", .{line});
            continue;
        }
        found = true;
        const members_colon = std.mem.lastIndexOfScalar(u8, line, ':') orelse return error.InvalidGroupFile;
        const members = line[members_colon + 1 ..];
        var existing = std.mem.splitScalar(u8, members, ',');
        while (existing.next()) |member| {
            if (std.mem.eql(u8, member, username)) {
                try output.writer.print("{s}\n", .{line});
                break;
            }
        } else {
            try output.writer.writeAll(line[0 .. members_colon + 1]);
            if (members.len != 0) {
                try output.writer.writeAll(members);
                try output.writer.writeByte(',');
            }
            try output.writer.print("{s}\n", .{username});
        }
    }
    if (!found) return error.MissingSecondaryGroup;
    return output.toOwnedSlice();
}

fn removeRecord(allocator: Allocator, content: []const u8, name: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, content.len);
    errdefer output.deinit();
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse line.len;
        if (std.mem.eql(u8, line[0..colon], name)) continue;
        try output.writer.print("{s}\n", .{line});
    }
    return output.toOwnedSlice();
}

fn removeUserFromGroups(allocator: Allocator, content: []const u8, username: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, content.len);
    errdefer output.deinit();
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first_colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidGroupFile;
        if (std.mem.eql(u8, line[0..first_colon], username)) continue;
        const members_colon = std.mem.lastIndexOfScalar(u8, line, ':') orelse return error.InvalidGroupFile;
        try output.writer.writeAll(line[0 .. members_colon + 1]);
        var members = std.mem.splitScalar(u8, line[members_colon + 1 ..], ',');
        var wrote_member = false;
        while (members.next()) |member| {
            if (member.len == 0 or std.mem.eql(u8, member, username)) continue;
            if (wrote_member) try output.writer.writeByte(',');
            try output.writer.writeAll(member);
            wrote_member = true;
        }
        try output.writer.writeByte('\n');
    }
    return output.toOwnedSlice();
}

test "typed customization applies files accounts SSH services and modules" {
    const io = std.testing.io;
    const spool_path = "test-os-customization.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("etc/passwd", "root:x:0:0::/root:/bin/bash\n", .{ .mode = 0o644 });
    try tree.putFileBytes("etc/shadow", "root:!:19000:0:99999:7:::\n", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/group", "root:x:0:\n", .{ .mode = 0o644 });
    try tree.putFileBytes(
        "usr/lib/systemd/system/example.service",
        "[Unit]\nDescription=example\n",
        .{ .mode = 0o644 },
    );

    const operations = [_]FilesystemOperation{
        .{ .put_file = .{
            .path = "/etc/application.conf",
            .source = .{ .inline_bytes = "enabled=true\n" },
            .metadata = .{ .mode = 0o640 },
        } },
        .{ .put_symlink = .{ .path = "/application.conf", .target = "etc/application.conf" } },
        .{ .set_metadata = .{ .path = "/etc/application.conf", .uid = 12, .gid = 34 } },
    };
    const groups = [_]Group{.{ .name = "admins", .gid = 2000 }};
    const users = [_]User{.{
        .name = "alice",
        .uid = 1000,
        .secondary_groups = &.{"admins"},
        .ssh_authorized_keys = &.{"ssh-ed25519 AAAATEST alice@example"},
        .passwordless_sudo = true,
    }};
    const services = [_]Service{.{ .name = "example.service", .state = .enabled }};
    const modules = [_]KernelModule{.{
        .name = "hv_netvsc",
        .load = true,
        .options = "ring_size=256",
    }};
    try apply(std.testing.allocator, &tree, .{
        .filesystem = &operations,
        .hostname = "custom-vm",
        .groups = &groups,
        .users = &users,
        .services = &services,
        .kernel_modules = &modules,
    }, 1_735_689_600);

    const hostname = try tree.readFileAlloc(std.testing.allocator, "etc/hostname", 1024);
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualStrings("custom-vm\n", hostname);
    const passwd = try tree.readFileAlloc(std.testing.allocator, "etc/passwd", 4096);
    defer std.testing.allocator.free(passwd);
    try std.testing.expect(std.mem.indexOf(u8, passwd, "alice:x:1000:1000::/home/alice:/bin/bash") != null);
    const groups_after = try tree.readFileAlloc(std.testing.allocator, "etc/group", 4096);
    defer std.testing.allocator.free(groups_after);
    try std.testing.expect(std.mem.indexOf(u8, groups_after, "admins:x:2000:alice") != null);
    const keys = try tree.readFileAlloc(std.testing.allocator, "home/alice/.ssh/authorized_keys", 4096);
    defer std.testing.allocator.free(keys);
    try std.testing.expectEqualStrings("ssh-ed25519 AAAATEST alice@example\n", keys);
    try std.testing.expectEqual(@as(u32, 12), tree.findNode("etc/application.conf").?.metadata.uid);
    try std.testing.expectEqual(root_tree.Kind.symlink, tree.findNode("etc/systemd/system/multi-user.target.wants/example.service").?.kind);
    var service_target_buffer: [512]u8 = undefined;
    const service_target = try testSymlinkTarget(
        &tree,
        &service_target_buffer,
        "etc/systemd/system/multi-user.target.wants/example.service",
    );
    try std.testing.expectEqualStrings("/usr/lib/systemd/system/example.service", service_target);
    const module_options = try tree.readFileAlloc(std.testing.allocator, "etc/modprobe.d/vmiz-options.conf", 4096);
    defer std.testing.allocator.free(module_options);
    try std.testing.expectEqualStrings("options hv_netvsc ring_size=256\n", module_options);
}

/// Reads a symlink's target out of the tree. `readFileAlloc` refuses a
/// non-file node, and the target is the point of every assertion below.
fn testSymlinkTarget(tree: *const RootTree, buffer: []u8, path: []const u8) ![]const u8 {
    const node = tree.findNode(path) orelse return error.MissingNode;
    try std.testing.expectEqual(root_tree.Kind.symlink, node.kind);
    const length = try tree.readNodeContent(path, buffer, 0);
    return buffer[0..length];
}

test "enabling a service on a target with no service manager is refused" {
    const io = std.testing.io;
    const spool_path = "test-os-no-service-manager.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    // A plausible root that is simply not systemd: it has the directories a
    // unit would live under the parents of, but no unit directory.
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putDirectory("usr/lib", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/rc.conf", "sshd_enable=\"YES\"\n", .{ .mode = 0o644 });

    const services = [_]Service{.{ .name = "sshd.service", .state = .enabled }};
    try std.testing.expectError(
        error.UnsupportedServiceManager,
        apply(std.testing.allocator, &tree, .{ .services = &services }, 1_735_689_600),
    );

    // The refusal has to happen before anything is written, or a failed run
    // still leaves the meaningless symlink this check exists to prevent.
    try std.testing.expect(tree.findNode("etc/systemd") == null);

    // Disabling is refused on the same grounds. It would otherwise be
    // vacuously satisfiable -- remove a link that was never there -- which is
    // a run reporting that it disabled a service on an image that has no way
    // to run services at all.
    const disable = [_]Service{.{ .name = "sshd.service", .state = .disabled }};
    try std.testing.expectError(
        error.UnsupportedServiceManager,
        apply(std.testing.allocator, &tree, .{ .services = &disable }, 1_735_689_600),
    );
}

test "enabling a service the target does not carry is refused rather than dangling" {
    const io = std.testing.io;
    const spool_path = "test-os-missing-unit.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putDirectory("usr/lib/systemd/system", .{ .mode = 0o755 });
    try tree.putFileBytes(
        "usr/lib/systemd/system/present.service",
        "[Unit]\nDescription=present\n",
        .{ .mode = 0o644 },
    );

    const services = [_]Service{.{ .name = "absent.service", .state = .enabled }};
    try std.testing.expectError(
        error.MissingServiceUnit,
        apply(std.testing.allocator, &tree, .{ .services = &services }, 1_735_689_600),
    );

    // Not a target that refuses everything: the unit that is there enables.
    const present = [_]Service{.{ .name = "present.service", .state = .enabled }};
    try apply(std.testing.allocator, &tree, .{ .services = &present }, 1_735_689_600);
    try std.testing.expectEqual(
        root_tree.Kind.symlink,
        tree.findNode("etc/systemd/system/multi-user.target.wants/present.service").?.kind,
    );
}

test "a unit in /etc is enabled by a link to /etc, not to /usr/lib" {
    const io = std.testing.io;
    const spool_path = "test-os-etc-unit.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    // The obvious workflow: inject a unit, then enable it. Injection puts it
    // in /etc, because that is where an administrator's unit belongs, and
    // linking it to /usr/lib -- which is what this used to do unconditionally
    // -- produces a symlink to a file that does not exist.
    const operations = [_]FilesystemOperation{.{ .put_file = .{
        .path = "/etc/systemd/system/appliance.service",
        .source = .{ .inline_bytes = "[Unit]\nDescription=appliance\n" },
    } }};
    const services = [_]Service{.{ .name = "appliance.service", .state = .enabled }};
    try apply(std.testing.allocator, &tree, .{
        .filesystem = &operations,
        .services = &services,
    }, 1_735_689_600);

    var target_buffer: [512]u8 = undefined;
    const target = try testSymlinkTarget(
        &tree,
        &target_buffer,
        "etc/systemd/system/multi-user.target.wants/appliance.service",
    );
    try std.testing.expectEqualStrings("/etc/systemd/system/appliance.service", target);

    // The link resolves to a node that is actually in the tree, which is the
    // property that was missing and the only one worth asserting.
    try std.testing.expect(tree.findNode(target[1..]) != null);
}

test "an /etc unit shadows a /usr/lib unit of the same name" {
    const io = std.testing.io;
    const spool_path = "test-os-unit-precedence.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("usr/lib/systemd/system/agent.service", "[Unit]\nDescription=shipped\n", .{ .mode = 0o644 });
    try tree.putFileBytes("etc/systemd/system/agent.service", "[Unit]\nDescription=override\n", .{ .mode = 0o644 });

    const services = [_]Service{.{ .name = "agent.service", .state = .enabled }};
    try apply(std.testing.allocator, &tree, .{ .services = &services }, 1_735_689_600);

    var target_buffer: [512]u8 = undefined;
    const target = try testSymlinkTarget(
        &tree,
        &target_buffer,
        "etc/systemd/system/multi-user.target.wants/agent.service",
    );
    // systemd resolves the administrator's copy, so enabling has to link to
    // the same file the running system would load. Both units exist here, so
    // this distinguishes the search order rather than finding the only one.
    try std.testing.expectEqualStrings("/etc/systemd/system/agent.service", target);
}

test "Azure generalization resets machine-specific owned-tree state" {
    const io = std.testing.io;
    const spool_path = "test-os-generalization.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("etc/hostname", "captured\n", .{ .mode = 0o644 });
    try tree.putFileBytes("etc/machine-id", "0123456789abcdef\n", .{ .mode = 0o444 });
    try tree.putFileBytes("etc/ssh/ssh_host_rsa_key", "private", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/ssh/sshd_config", "keep", .{ .mode = 0o644 });
    try tree.putFileBytes("var/lib/azagent/state", "captured", .{ .mode = 0o600 });
    try tree.putFileBytes("var/lib/dhcp/lease", "captured", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/resolv.conf", "nameserver 10.0.0.1\n", .{ .mode = 0o644 });
    try tree.putFileBytes("var/lib/systemd/random-seed", "captured", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/passwd", "root:x:0:0::/root:/bin/bash\ndaemon:x:2:2::/:/usr/sbin/nologin\nalice:x:1000:1000::/srv/alice:/bin/bash\n", .{ .mode = 0o644 });
    try tree.putFileBytes("etc/shadow", "root:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/group", "root:x:0:\nwheel:x:10:alice\nalice:x:1000:\n", .{ .mode = 0o644 });
    try tree.putFileBytes("srv/alice/.ssh/authorized_keys", "captured-key\n", .{ .mode = 0o600 });
    try tree.putFileBytes("etc/sudoers.d/alice", "alice ALL=(ALL) NOPASSWD: ALL\n", .{ .mode = 0o440 });
    try generalize(std.testing.allocator, &tree, .{ .azure = .{ .remove_users = &.{"alice"} } });

    const hostname = try tree.readFileAlloc(std.testing.allocator, "etc/hostname", 1024);
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualStrings("localhost.localdomain\n", hostname);
    const machine_id = try tree.readFileAlloc(std.testing.allocator, "etc/machine-id", 1024);
    defer std.testing.allocator.free(machine_id);
    try std.testing.expectEqual(@as(usize, 0), machine_id.len);
    try std.testing.expect(tree.findNode("etc/ssh/ssh_host_rsa_key") == null);
    try std.testing.expect(tree.findNode("etc/ssh/sshd_config") != null);
    try std.testing.expect(tree.findNode("var/lib/azagent") == null);
    try std.testing.expect(tree.findNode("var/lib/dhcp") == null);
    try std.testing.expect(tree.findNode("etc/resolv.conf") == null);
    const random_seed = try tree.readFileAlloc(std.testing.allocator, "var/lib/systemd/random-seed", 1024);
    defer std.testing.allocator.free(random_seed);
    try std.testing.expectEqual(@as(usize, 0), random_seed.len);
    try std.testing.expect(tree.findNode("srv/alice") == null);
    try std.testing.expect(tree.findNode("etc/sudoers.d/alice") == null);
    const passwd = try tree.readFileAlloc(std.testing.allocator, "etc/passwd", 4096);
    defer std.testing.allocator.free(passwd);
    try std.testing.expect(std.mem.indexOf(u8, passwd, "alice:") == null);
    const group = try tree.readFileAlloc(std.testing.allocator, "etc/group", 4096);
    defer std.testing.allocator.free(group);
    try std.testing.expect(std.mem.indexOf(u8, group, "wheel:x:10:alice") == null);
}

test "a declared mtime is stamped on injected nodes and left to the build default otherwise" {
    const io = std.testing.io;
    const spool_path = "test-os-customization-mtime.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    const backdated: i64 = 1_400_000_000;
    try apply(std.testing.allocator, &tree, .{ .filesystem = &.{
        .{ .put_directory = .{ .path = "/opt/vendor", .metadata = .{ .mode = 0o755, .mtime = backdated } } },
        .{ .put_file = .{
            .path = "/opt/vendor/config",
            .source = .{ .inline_bytes = "value\n" },
            .metadata = .{ .mode = 0o644, .mtime = backdated },
        } },
        .{ .put_symlink = .{
            .path = "/opt/vendor/current",
            .target = "config",
            .metadata = .{ .mode = 0o777, .mtime = backdated },
        } },
        .{ .put_file = .{
            .path = "/opt/vendor/undated",
            .source = .{ .inline_bytes = "value\n" },
            .metadata = .{ .mode = 0o644 },
        } },
    } }, 0);

    inline for (.{ "opt/vendor", "opt/vendor/config", "opt/vendor/current" }) |path| {
        const node = tree.findNode(path) orelse return error.MissingNode;
        try std.testing.expectEqual(@as(?i64, backdated), node.metadata.mtime);
    }
    const undated = tree.findNode("opt/vendor/undated") orelse return error.MissingNode;
    try std.testing.expectEqual(@as(?i64, null), undated.metadata.mtime);
}

test "set_metadata changes only the fields it states, mtime included" {
    const io = std.testing.io;
    const spool_path = "test-os-customization-mtime-change.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    const original: i64 = 1_400_000_000;
    const restamped: i64 = 1_500_000_000;
    try tree.putFileBytes("etc/config", "value\n", .{ .mode = 0o644, .uid = 7, .mtime = original });

    try apply(std.testing.allocator, &tree, .{ .filesystem = &.{
        .{ .set_metadata = .{ .path = "/etc/config", .mtime = restamped } },
    } }, 0);
    const restamped_node = tree.findNode("etc/config") orelse return error.MissingNode;
    try std.testing.expectEqual(@as(?i64, restamped), restamped_node.metadata.mtime);
    try std.testing.expectEqual(@as(u32, 7), restamped_node.metadata.uid);

    try apply(std.testing.allocator, &tree, .{ .filesystem = &.{
        .{ .set_metadata = .{ .path = "/etc/config", .mode = 0o600 } },
    } }, 0);
    const kept = tree.findNode("etc/config") orelse return error.MissingNode;
    try std.testing.expectEqual(@as(?i64, restamped), kept.metadata.mtime);
    try std.testing.expectEqual(@as(u16, 0o600), kept.metadata.mode);
}

test "Azure generalization leaves a resolv.conf symlink pointing at the resolver" {
    const io = std.testing.io;
    const spool_path = "test-os-generalization-resolver-link.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putSymlink("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf", .{ .mode = 0o777 });
    try generalize(std.testing.allocator, &tree, .{ .azure = .{} });

    var buffer: [256]u8 = undefined;
    const target = try testSymlinkTarget(&tree, &buffer, "etc/resolv.conf");
    try std.testing.expectEqualStrings("../run/systemd/resolve/stub-resolv.conf", target);
}

test "Azure generalization keeps a resolv.conf file when the caller opts out" {
    const io = std.testing.io;
    const spool_path = "test-os-generalization-resolver-kept.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("etc/resolv.conf", "nameserver 10.0.0.1\n", .{ .mode = 0o644 });
    try generalize(std.testing.allocator, &tree, .{ .azure = .{ .remove_resolver_configuration = false } });

    const resolver = try tree.readFileAlloc(std.testing.allocator, "etc/resolv.conf", 1024);
    defer std.testing.allocator.free(resolver);
    try std.testing.expectEqualStrings("nameserver 10.0.0.1\n", resolver);
}

test "Azure generalization tolerates an image with no resolv.conf at all" {
    const io = std.testing.io;
    const spool_path = "test-os-generalization-resolver-absent.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try generalize(std.testing.allocator, &tree, .{ .azure = .{} });
    try std.testing.expect(tree.findNode("etc/resolv.conf") == null);
}

test "Azure generalization rejects shared home removal before mutation" {
    const io = std.testing.io;
    const spool_path = "test-os-shared-home-generalization.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("etc/hostname", "captured\n", .{ .mode = 0o644 });
    try tree.putFileBytes(
        "etc/passwd",
        "alice:x:1000:1000::/srv/alice:/bin/bash\nbob:x:1001:1001::/srv:/bin/bash\n",
        .{ .mode = 0o644 },
    );
    try std.testing.expectError(
        error.SharedUserHome,
        generalize(std.testing.allocator, &tree, .{ .azure = .{ .remove_users = &.{"alice"} } }),
    );

    const hostname = try tree.readFileAlloc(std.testing.allocator, "etc/hostname", 1024);
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualStrings("captured\n", hostname);
}

test "Azure generalization does not infer a home for an absent user" {
    const io = std.testing.io;
    const spool_path = "test-os-absent-user-generalization.spool";
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("etc/passwd", "bob:x:1001:1001::/home/alice:/bin/bash\n", .{ .mode = 0o644 });
    try tree.putFileBytes("home/alice/authorized_keys", "bob-key\n", .{ .mode = 0o600 });
    try generalize(std.testing.allocator, &tree, .{ .azure = .{
        .reset_hostname = false,
        .clear_machine_id = false,
        .remove_ssh_host_keys = false,
        .remove_agent_state = false,
        .remove_dhcp_leases = false,
        .clear_random_seed = false,
        .remove_users = &.{"alice"},
    } });

    try std.testing.expect(tree.findNode("home/alice/authorized_keys") != null);
}

test "a created account is never born with an expired password" {
    var buf: [24]u8 = undefined;

    // A build with no meaningful clock must not emit 0: shadow(5) reads that
    // as "must change password at next login", which PAM enforces even when
    // the user authenticated with a key, locking the account out entirely.
    try std.testing.expectEqualStrings("", formatShadowLastChange(&buf, 0));
    try std.testing.expectEqualStrings("", formatShadowLastChange(&buf, 86_399));

    // A real timestamp still records the day it was set, so an image built
    // with SOURCE_DATE_EPOCH keeps reporting a truthful last-change date.
    try std.testing.expectEqualStrings("1", formatShadowLastChange(&buf, 86_400));
    try std.testing.expectEqualStrings("19000", formatShadowLastChange(&buf, 19_000 * 86_400));
}
