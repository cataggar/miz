//! OCI image configuration to OCI runtime configuration conversion.
const std = @import("std");
const model = @import("model.zig");

const Io = std.Io;

const RuntimeSpec = struct {
    ociVersion: []const u8 = "1.2.0",
    root: Root,
    process: Process,
    hostname: []const u8 = "vmiz",
    mounts: []const Mount,
    linux: Linux,
    annotations: std.json.Value,
};

const Root = struct {
    path: []const u8 = "rootfs",
    readonly: bool = false,
};

const Process = struct {
    terminal: bool = false,
    user: User,
    args: []const []const u8,
    env: []const []const u8,
    cwd: []const u8,
    capabilities: Capabilities,
    rlimits: []const Rlimit,
    noNewPrivileges: bool = true,
};

const User = struct {
    uid: u32,
    gid: u32,
    additionalGids: []const u32,
};

const Capabilities = struct {
    bounding: []const []const u8,
    effective: []const []const u8,
    inheritable: []const []const u8,
    permitted: []const []const u8,
    ambient: []const []const u8,
};

const Rlimit = struct {
    type: []const u8,
    hard: u64,
    soft: u64,
};

const Mount = struct {
    destination: []const u8,
    type: []const u8,
    source: []const u8,
    options: []const []const u8,
};

const Linux = struct {
    namespaces: []const Namespace,
    maskedPaths: []const []const u8,
    readonlyPaths: []const []const u8,
    uidMappings: ?[]const IdMapping = null,
    gidMappings: ?[]const IdMapping = null,
};

const IdMapping = struct {
    containerID: u32,
    hostID: u32,
    size: u32,
};

const Namespace = struct {
    type: []const u8,
};

const passwd_limit = 1024 * 1024;

pub const Options = struct {
    rootless: bool = false,
};

pub fn generate(
    io: Io,
    allocator: std.mem.Allocator,
    rootfs: Io.Dir,
    image: model.ImageConfiguration,
    options: Options,
) ![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const execution: model.ImageExecutionConfig = image.config orelse .{};

    const resolved_user = try resolveUser(io, arena, rootfs, execution.User);
    if (options.rootless and
        (resolved_user.uid != 0 or
            resolved_user.gid != 0 or
            resolved_user.additional_gids.len != 0))
    {
        return error.RootlessUserNotMapped;
    }
    const args = try commandArgs(arena, execution);
    const env = try environment(arena, execution.Env orelse &.{}, resolved_user.home);
    const annotations = try runtimeAnnotations(arena, image, execution);
    const mounts = try runtimeMounts(arena, execution);
    const capability_names = &.{
        "CAP_AUDIT_WRITE",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
    };
    const spec = RuntimeSpec{
        .root = .{},
        .process = .{
            .user = .{
                .uid = resolved_user.uid,
                .gid = resolved_user.gid,
                .additionalGids = resolved_user.additional_gids,
            },
            .args = args,
            .env = env,
            .cwd = if (execution.WorkingDir) |cwd|
                if (cwd.len == 0) "/" else cwd
            else
                "/",
            .capabilities = .{
                .bounding = capability_names,
                .effective = capability_names,
                .inheritable = &.{},
                .permitted = capability_names,
                .ambient = &.{},
            },
            .rlimits = &.{.{
                .type = "RLIMIT_NOFILE",
                .hard = 1024,
                .soft = 1024,
            }},
        },
        .mounts = mounts,
        .linux = .{
            .namespaces = if (options.rootless)
                &.{
                    .{ .type = "user" },
                    .{ .type = "cgroup" },
                    .{ .type = "pid" },
                    .{ .type = "network" },
                    .{ .type = "ipc" },
                    .{ .type = "uts" },
                    .{ .type = "mount" },
                }
            else
                &.{
                    .{ .type = "cgroup" },
                    .{ .type = "pid" },
                    .{ .type = "network" },
                    .{ .type = "ipc" },
                    .{ .type = "uts" },
                    .{ .type = "mount" },
                },
            .maskedPaths = &.{
                "/proc/acpi",
                "/proc/asound",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug",
                "/proc/scsi",
                "/sys/firmware",
            },
            .readonlyPaths = &.{
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
            },
            .uidMappings = if (options.rootless) &.{.{
                .containerID = 0,
                .hostID = currentUid(),
                .size = 1,
            }} else null,
            .gidMappings = if (options.rootless) &.{.{
                .containerID = 0,
                .hostID = currentGid(),
                .size = 1,
            }} else null,
        },
        .annotations = annotations,
    };
    return std.json.Stringify.valueAlloc(allocator, spec, .{ .whitespace = .indent_2 });
}

fn currentUid() u32 {
    return if (@import("builtin").os.tag == .linux) std.os.linux.geteuid() else 0;
}

fn currentGid() u32 {
    return if (@import("builtin").os.tag == .linux) std.os.linux.getegid() else 0;
}

const ResolvedUser = struct {
    uid: u32,
    gid: u32,
    additional_gids: []const u32,
    home: []const u8,
};

const PasswdEntry = struct {
    name: []const u8,
    uid: u32,
    gid: u32,
    home: []const u8,
};

const GroupEntry = struct {
    name: []const u8,
    gid: u32,
    members: []const u8,
};

fn resolveUser(
    io: Io,
    allocator: std.mem.Allocator,
    rootfs: Io.Dir,
    requested: ?[]const u8,
) !ResolvedUser {
    const value = requested orelse "";
    const separator = std.mem.indexOfScalar(u8, value, ':');
    const user_text = if (separator) |index| value[0..index] else value;
    const group_text = if (separator) |index| value[index + 1 ..] else null;
    const passwd = readRootfsFile(io, allocator, rootfs, "etc/passwd") catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    const groups = readRootfsFile(io, allocator, rootfs, "etc/group") catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };

    var passwd_entry: ?PasswdEntry = null;
    const uid = std.fmt.parseUnsigned(u32, user_text, 10) catch blk: {
        if (user_text.len == 0) break :blk 0;
        passwd_entry = findPasswdByName(passwd orelse return error.UserNotFound, user_text) orelse
            return error.UserNotFound;
        break :blk passwd_entry.?.uid;
    };
    if (passwd_entry == null and passwd != null) {
        passwd_entry = findPasswdByUid(passwd.?, uid);
    }

    var explicit_group = false;
    const gid = if (group_text) |text| blk: {
        explicit_group = true;
        break :blk std.fmt.parseUnsigned(u32, text, 10) catch {
            const group = findGroupByName(groups orelse return error.GroupNotFound, text) orelse
                return error.GroupNotFound;
            break :blk group.gid;
        };
    } else if (passwd_entry) |entry|
        entry.gid
    else
        0;

    var additional = std.array_list.Managed(u32).init(allocator);
    if (!explicit_group and passwd_entry != null and groups != null) {
        var lines = std.mem.splitScalar(u8, groups.?, '\n');
        while (lines.next()) |line| {
            const group = parseGroup(line) orelse continue;
            if (group.gid == gid or !memberListContains(group.members, passwd_entry.?.name)) {
                continue;
            }
            try additional.append(group.gid);
        }
        std.mem.sort(u32, additional.items, {}, std.sort.asc(u32));
    }
    return .{
        .uid = uid,
        .gid = gid,
        .additional_gids = try additional.toOwnedSlice(),
        .home = if (passwd_entry) |entry|
            if (entry.home.len == 0) "/" else entry.home
        else
            "/",
    };
}

fn readRootfsFile(
    io: Io,
    allocator: std.mem.Allocator,
    rootfs: Io.Dir,
    path: []const u8,
) ![]u8 {
    const parent_path = std.fs.path.dirname(path) orelse "";
    const basename = std.fs.path.basename(path);
    var current = rootfs;
    var current_owned = false;
    defer if (current_owned) current.close(io);
    var components = std.mem.splitScalar(u8, parent_path, '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        const next = try current.openDir(io, component, .{
            .follow_symlinks = false,
        });
        if (current_owned) current.close(io);
        current = next;
        current_owned = true;
    }
    var file = try current.openFile(io, basename, .{
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.InvalidAccountFile;
    if (stat.size > passwd_limit) return error.StreamTooLong;
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(bytes);
    const count = try file.readPositionalAll(io, bytes, 0);
    if (count != bytes.len) return error.InvalidAccountFile;
    return bytes;
}

fn commandArgs(
    allocator: std.mem.Allocator,
    config: model.ImageExecutionConfig,
) ![]const []const u8 {
    var args = std.array_list.Managed([]const u8).init(allocator);
    if (config.Entrypoint) |values| try args.appendSlice(values);
    if (config.Cmd) |values| try args.appendSlice(values);
    if (args.items.len == 0) try args.append("/bin/sh");
    return args.toOwnedSlice();
}

fn environment(
    allocator: std.mem.Allocator,
    source: []const []const u8,
    home: []const u8,
) ![]const []const u8 {
    var env = std.array_list.Managed([]const u8).init(allocator);
    try env.appendSlice(source);
    for (source) |value| {
        if (std.mem.startsWith(u8, value, "HOME=")) return env.toOwnedSlice();
    }
    try env.append(try std.fmt.allocPrint(allocator, "HOME={s}", .{home}));
    return env.toOwnedSlice();
}

fn runtimeAnnotations(
    allocator: std.mem.Allocator,
    image: model.ImageConfiguration,
    config: model.ImageExecutionConfig,
) !std.json.Value {
    var annotations: std.json.ObjectMap = .empty;
    if (image.os) |value| try annotations.put(allocator, "org.opencontainers.image.os", .{ .string = value });
    if (image.architecture) |value| try annotations.put(allocator, "org.opencontainers.image.architecture", .{ .string = value });
    if (image.variant) |value| try annotations.put(allocator, "org.opencontainers.image.variant", .{ .string = value });
    if (image.created) |value| try annotations.put(allocator, "org.opencontainers.image.created", .{ .string = value });
    if (image.author) |value| try annotations.put(allocator, "org.opencontainers.image.author", .{ .string = value });
    if (config.StopSignal) |value| {
        try annotations.put(allocator, "org.opencontainers.image.stopSignal", .{ .string = value });
    }
    if (config.ExposedPorts) |ports| {
        if (ports != .object) return error.InvalidExposedPorts;
        const keys = try sortedObjectKeys(allocator, ports.object);
        var joined = Io.Writer.Allocating.init(allocator);
        for (keys, 0..) |key, index| {
            if (index != 0) try joined.writer.writeByte(',');
            try joined.writer.writeAll(key);
        }
        try annotations.put(allocator, "org.opencontainers.image.exposedPorts", .{
            .string = try joined.toOwnedSlice(),
        });
    }
    if (config.Labels) |labels| {
        if (labels != .object) return error.InvalidLabels;
        var iterator = labels.object.iterator();
        while (iterator.next()) |item| {
            if (item.value_ptr.* != .string) return error.InvalidLabels;
            try annotations.put(allocator, item.key_ptr.*, .{ .string = item.value_ptr.string });
        }
    }
    return .{ .object = annotations };
}

fn runtimeMounts(
    allocator: std.mem.Allocator,
    config: model.ImageExecutionConfig,
) ![]const Mount {
    var mounts = std.array_list.Managed(Mount).init(allocator);
    try mounts.appendSlice(&.{
        .{ .destination = "/proc", .type = "proc", .source = "proc", .options = &.{ "nosuid", "noexec", "nodev" } },
        .{ .destination = "/dev", .type = "tmpfs", .source = "tmpfs", .options = &.{ "nosuid", "strictatime", "mode=755", "size=65536k" } },
        .{ .destination = "/dev/pts", .type = "devpts", .source = "devpts", .options = &.{ "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5" } },
        .{ .destination = "/dev/shm", .type = "tmpfs", .source = "shm", .options = &.{ "nosuid", "noexec", "nodev", "mode=1777", "size=65536k" } },
        .{ .destination = "/dev/mqueue", .type = "mqueue", .source = "mqueue", .options = &.{ "nosuid", "noexec", "nodev" } },
        .{ .destination = "/sys", .type = "sysfs", .source = "sysfs", .options = &.{ "nosuid", "noexec", "nodev", "ro" } },
        .{ .destination = "/sys/fs/cgroup", .type = "cgroup", .source = "cgroup", .options = &.{ "nosuid", "noexec", "nodev", "relatime", "ro" } },
    });
    if (config.Volumes) |volumes| {
        if (volumes != .object) return error.InvalidVolumes;
        const keys = try sortedObjectKeys(allocator, volumes.object);
        for (keys) |destination| {
            if (!validAbsoluteContainerPath(destination)) return error.InvalidVolumePath;
            try mounts.append(.{
                .destination = destination,
                .type = "tmpfs",
                .source = "none",
                .options = &.{ "rw", "nosuid", "nodev", "noexec", "relatime" },
            });
        }
    }
    return mounts.toOwnedSlice();
}

fn sortedObjectKeys(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
) ![]const []const u8 {
    const keys = try allocator.alloc([]const u8, object.count());
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |item| : (index += 1) keys[index] = item.key_ptr.*;
    std.mem.sort([]const u8, keys, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.lessThan);
    return keys;
}

fn validAbsoluteContainerPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

fn findPasswdByName(bytes: []const u8, name: []const u8) ?PasswdEntry {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const entry = parsePasswd(line) orelse continue;
        if (std.mem.eql(u8, entry.name, name)) return entry;
    }
    return null;
}

fn findPasswdByUid(bytes: []const u8, uid: u32) ?PasswdEntry {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const entry = parsePasswd(line) orelse continue;
        if (entry.uid == uid) return entry;
    }
    return null;
}

fn parsePasswd(line: []const u8) ?PasswdEntry {
    var fields = std.mem.splitScalar(u8, line, ':');
    const name = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    const uid = std.fmt.parseUnsigned(u32, fields.next() orelse return null, 10) catch return null;
    const gid = std.fmt.parseUnsigned(u32, fields.next() orelse return null, 10) catch return null;
    _ = fields.next() orelse return null;
    const home = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    if (fields.next() != null) return null;
    return .{ .name = name, .uid = uid, .gid = gid, .home = home };
}

fn findGroupByName(bytes: []const u8, name: []const u8) ?GroupEntry {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const entry = parseGroup(line) orelse continue;
        if (std.mem.eql(u8, entry.name, name)) return entry;
    }
    return null;
}

fn parseGroup(line: []const u8) ?GroupEntry {
    var fields = std.mem.splitScalar(u8, line, ':');
    const name = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    const gid = std.fmt.parseUnsigned(u32, fields.next() orelse return null, 10) catch return null;
    const members = fields.next() orelse return null;
    if (fields.next() != null) return null;
    return .{ .name = name, .gid = gid, .members = members };
}

fn memberListContains(members: []const u8, name: []const u8) bool {
    var iterator = std.mem.splitScalar(u8, members, ',');
    while (iterator.next()) |member| {
        if (std.mem.eql(u8, member, name)) return true;
    }
    return false;
}

test "runtime config translates command user environment volumes and annotations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-runtime-config-root";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path ++ "/etc");
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);
    try root.writeFile(io, .{
        .sub_path = "etc/passwd",
        .data = "app:x:1000:1000::/home/app:/bin/sh\n",
    });
    try root.writeFile(io, .{
        .sub_path = "etc/group",
        .data = "app:x:1000:\nextra:x:2000:app\n",
    });
    const image_json =
        \\{"created":"2026-07-24T00:00:00Z","author":"vmiz","architecture":"amd64","os":"linux","config":{"User":"app","Env":["PATH=/bin"],"Entrypoint":["/bin/app"],"Cmd":["serve"],"WorkingDir":"/work","ExposedPorts":{"8080/tcp":{}},"Volumes":{"/data":{}},"Labels":{"org.example":"value"},"StopSignal":"SIGTERM"},"rootfs":{"type":"layers","diff_ids":[]}}
    ;
    const parsed = try std.json.parseFromSlice(
        model.ImageConfiguration,
        allocator,
        image_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const bytes = try generate(io, allocator, root, parsed.value, .{});
    defer allocator.free(bytes);
    const runtime = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer runtime.deinit();
    const object = runtime.value.object;
    const process = object.get("process").?.object;
    try std.testing.expectEqualStrings("/bin/app", process.get("args").?.array.items[0].string);
    try std.testing.expectEqualStrings("serve", process.get("args").?.array.items[1].string);
    try std.testing.expectEqual(@as(i64, 1000), process.get("user").?.object.get("uid").?.integer);
    try std.testing.expectEqual(
        @as(i64, 2000),
        process.get("user").?.object.get("additionalGids").?.array.items[0].integer,
    );
    try std.testing.expectEqualStrings(
        "HOME=/home/app",
        process.get("env").?.array.items[1].string,
    );
    try std.testing.expectEqualStrings("/work", process.get("cwd").?.string);
    try std.testing.expectEqualStrings(
        "8080/tcp",
        object.get("annotations").?.object.get("org.opencontainers.image.exposedPorts").?.string,
    );
    try std.testing.expectEqualStrings(
        "value",
        object.get("annotations").?.object.get("org.example").?.string,
    );
    try std.testing.expectEqualStrings(
        "/data",
        object.get("mounts").?.array.items[7].object.get("destination").?.string,
    );
}

test "runtime config does not follow account files outside rootfs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-runtime-config-symlink-root";
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDir(io, root_path, .default_dir);
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);
    try root.symLink(io, "/etc", "etc", .{});
    const image = model.ImageConfiguration{
        .architecture = "amd64",
        .os = "linux",
        .config = .{ .User = "root" },
        .rootfs = .{ .type = "layers", .diff_ids = &.{} },
    };
    try std.testing.expectError(
        error.NotDir,
        generate(io, allocator, root, image, .{}),
    );
}
