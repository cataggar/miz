const std = @import("std");
const miz = @import("miz");

pub const Loaded = struct {
    os: miz.customize.OsCustomization,
    generalization: miz.customize.GeneralizationPolicy,
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    config_path: ?[]const u8,
    source_paths: []const []const u8,
) !Loaded {
    const path = config_path orelse {
        if (source_paths.len != 0) return error.CustomizationSourcesWithoutConfig;
        return .{ .os = .{}, .generalization = .none };
    };
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    const parsed = try std.json.parseFromSlice(
        miz.customization_wire.Configuration,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false },
    );
    return map(allocator, parsed.value, source_paths);
}

pub fn map(
    allocator: std.mem.Allocator,
    wire: miz.customization_wire.Configuration,
    source_paths: []const []const u8,
) !Loaded {
    const filesystem = try allocator.alloc(
        miz.customize.FilesystemOperation,
        wire.os.filesystem.len,
    );
    for (wire.os.filesystem, 0..) |operation, index| {
        filesystem[index] = switch (operation) {
            .put_file => |file| .{ .put_file = .{
                .path = file.path,
                .source = .{ .host_path = if (file.source_index < source_paths.len)
                    source_paths[file.source_index]
                else
                    return error.CustomizationSourceIndexOutOfBounds },
                .metadata = try convertMetadata(allocator, file.metadata),
            } },
            .put_directory => |directory| .{ .put_directory = .{
                .path = directory.path,
                .metadata = try convertMetadata(allocator, directory.metadata),
            } },
            .put_symlink => |link| .{ .put_symlink = .{
                .path = link.path,
                .target = link.target,
                .metadata = try convertMetadata(allocator, link.metadata),
            } },
            .remove => |remove_path| .{ .remove = remove_path },
            .set_metadata => |change| .{ .set_metadata = .{
                .path = change.path,
                .mode = change.mode,
                .uid = change.uid,
                .gid = change.gid,
                .mtime = change.mtime,
                .xattrs = if (change.xattrs) |xattrs|
                    try convertXattrs(allocator, xattrs)
                else
                    null,
            } },
        };
    }
    const groups = try allocator.alloc(miz.customize.Group, wire.os.groups.len);
    for (wire.os.groups, 0..) |group, index| groups[index] = .{
        .name = group.name,
        .gid = group.gid,
        .members = group.members,
    };
    const users = try allocator.alloc(miz.customize.User, wire.os.users.len);
    for (wire.os.users, 0..) |user, index| users[index] = .{
        .name = user.name,
        .uid = user.uid,
        .gid = user.gid,
        .primary_group = user.primary_group,
        .secondary_groups = user.secondary_groups,
        .home = user.home,
        .shell = user.shell,
        .password = switch (user.password) {
            .locked => .locked,
            .prehashed => |value| .{ .prehashed = value },
        },
        .ssh_authorized_keys = user.ssh_authorized_keys,
        .passwordless_sudo = user.passwordless_sudo,
    };
    const services = try allocator.alloc(miz.customize.Service, wire.os.services.len);
    for (wire.os.services, 0..) |service, index| services[index] = .{
        .name = service.name,
        .state = switch (service.state) {
            .enabled => .enabled,
            .disabled => .disabled,
        },
    };
    const modules = try allocator.alloc(miz.customize.KernelModule, wire.os.kernel_modules.len);
    for (wire.os.kernel_modules, 0..) |module, index| modules[index] = .{
        .name = module.name,
        .load = module.load,
        .disabled = module.disabled,
        .options = module.options,
    };
    return .{
        .os = .{
            .filesystem = filesystem,
            .hostname = wire.os.hostname,
            .groups = groups,
            .users = users,
            .services = services,
            .kernel_modules = modules,
        },
        .generalization = switch (wire.generalization) {
            .none => .none,
            .azure => |options| .{ .azure = .{
                .reset_hostname = options.reset_hostname,
                .clear_machine_id = options.clear_machine_id,
                .remove_ssh_host_keys = options.remove_ssh_host_keys,
                .remove_agent_state = options.remove_agent_state,
                .remove_dhcp_leases = options.remove_dhcp_leases,
                .remove_logs = options.remove_logs,
                .remove_caches = options.remove_caches,
                .clear_random_seed = options.clear_random_seed,
                .remove_users = options.remove_users,
            } },
        },
    };
}

fn convertMetadata(
    allocator: std.mem.Allocator,
    metadata: miz.customization_wire.Metadata,
) !miz.customize.Metadata {
    return .{
        .mode = metadata.mode,
        .uid = metadata.uid,
        .gid = metadata.gid,
        .mtime = metadata.mtime,
        .xattrs = try convertXattrs(allocator, metadata.xattrs),
    };
}

fn convertXattrs(
    allocator: std.mem.Allocator,
    xattrs: []const miz.customization_wire.Xattr,
) ![]const miz.ext4.Xattr {
    const converted = try allocator.alloc(miz.ext4.Xattr, xattrs.len);
    for (xattrs, 0..) |xattr, index| converted[index] = .{
        .name = xattr.name,
        .value = xattr.value,
    };
    return converted;
}

test "map resolves customization files from the shared source index space" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const loaded = try map(arena.allocator(), .{ .os = .{ .filesystem = &.{
        .{ .put_file = .{
            .path = "/etc/rebuilt.conf",
            .source_index = 1,
        } },
    } } }, &.{ "existing-replacement", "rebuild-source" });

    try std.testing.expectEqual(@as(usize, 1), loaded.os.filesystem.len);
    try std.testing.expectEqualStrings(
        "rebuild-source",
        loaded.os.filesystem[0].put_file.source.host_path,
    );
}
