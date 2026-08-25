pub const api_version: u32 = 2;

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const Metadata = struct {
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: ?i64 = null,
    xattrs: []const Xattr = &.{},
};

pub const PutFile = struct {
    path: []const u8,
    source_index: usize,
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
    mtime: ?i64 = null,
    xattrs: ?[]const Xattr = null,
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
    remove_logs: bool = false,
    remove_caches: bool = false,
    clear_random_seed: bool = true,
    remove_users: []const []const u8 = &.{},
};

pub const GeneralizationPolicy = union(enum) {
    none,
    azure: AzureGeneralization,
};

pub const Configuration = struct {
    os: OsCustomization = .{},
    generalization: GeneralizationPolicy = .none,
};
