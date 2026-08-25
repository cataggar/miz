//! Transport-aware OCI operations and editable runtime bundles.

const std = @import("std");
const builtin = @import("builtin");
const miz = @import("miz");

const Io = std.Io;
const oci = miz.oci;

const usage =
    \\usage:
    \\  miz oci copy [options] <source> <destination>
    \\  miz oci inspect [options] <source>
    \\  miz oci list-tags [options] docker://<registry>/<repository>
    \\  miz oci pin [options] docker://<registry>/<repository>:<tag>
    \\  miz oci unpack [options] --image oci:<layout>[:tag] <bundle>
    \\  miz oci repack --image oci:<layout>:<tag> <bundle>
    \\  miz oci config [options] --image oci:<layout>[:tag]
    \\
    \\copy options:
    \\  --all
    \\  --override-os <name>
    \\  --override-arch <name>
    \\  --override-variant <name>
    \\  --src-authfile <path>       --dest-authfile <path>
    \\  --src-tls-ca <path>         --dest-tls-ca <path>
    \\  --src-plain-http            --dest-plain-http
    \\
    \\inspect options:
    \\  --all
    \\  --override-os <name>
    \\  --override-arch <name>
    \\  --override-variant <name>
    \\  --authfile <path>
    \\  --tls-ca <path>
    \\  --plain-http
    \\
    \\list-tags options:
    \\  --authfile <path>
    \\  --tls-ca <path>
    \\  --plain-http
    \\
    \\pin options:
    \\  --authfile <path>
    \\  --tls-ca <path>
    \\  --plain-http
    \\  --json
    \\
    \\unpack options:
    \\  --image <reference>
    \\  --override-os <name>
    \\  --override-arch <name>
    \\  --override-variant <name>
    \\  --rootless
    \\  --force
    \\
    \\repack options:
    \\  --image <reference>
    \\  --compression <same|gzip|none>
    \\
    \\config options:
    \\  --image <reference>
    \\  --override-os <name>
    \\  --override-arch <name>
    \\  --override-variant <name>
    \\
;

const ParseError = error{
    DuplicateOption,
    MissingOptionValue,
    InvalidOption,
    InvalidArguments,
    ConflictingPlatformOptions,
    InvalidPlatform,
    InvalidTransportOption,
};

const EndpointOptions = struct {
    authfile: ?[]const u8 = null,
    tls_ca: ?[]const u8 = null,
    plain_http: bool = false,
    plain_http_set: bool = false,

    fn any(self: EndpointOptions) bool {
        return self.authfile != null or self.tls_ca != null or self.plain_http_set;
    }

    fn registry(self: EndpointOptions) oci.registry.Options {
        return .{
            .authfile = self.authfile,
            .tls_ca = self.tls_ca,
            .plain_http = self.plain_http,
        };
    }
};

const PlatformOptions = struct {
    all: bool = false,
    all_set: bool = false,
    os: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    variant: ?[]const u8 = null,

    fn graph(self: PlatformOptions) ParseError!oci.copy.Options {
        if (self.all and
            (self.os != null or self.architecture != null or self.variant != null))
        {
            return error.ConflictingPlatformOptions;
        }
        if (self.all) return .{ .mode = .all };
        const os = self.os orelse hostOs();
        const architecture = self.architecture orelse hostArchitecture();
        if (!validPlatformComponent(os) or
            !validPlatformComponent(architecture) or
            (self.variant != null and !validPlatformComponent(self.variant.?)))
        {
            return error.InvalidPlatform;
        }
        return .{
            .mode = .{ .selected = .{
                .os = os,
                .architecture = architecture,
                .variant = self.variant,
            } },
            .platform_selection_explicit = self.os != null or
                self.architecture != null or self.variant != null,
        };
    }

    fn inspect(self: PlatformOptions) ParseError!oci.registry.InspectOptions {
        const options = try self.graph();
        return .{ .mode = options.mode, .max_depth = options.max_depth };
    }

    fn selected(self: PlatformOptions) ParseError!oci.model.Platform {
        if (self.all_set) return error.ConflictingPlatformOptions;
        const os = self.os orelse hostOs();
        const architecture = self.architecture orelse hostArchitecture();
        if (!validPlatformComponent(os) or
            !validPlatformComponent(architecture) or
            (self.variant != null and !validPlatformComponent(self.variant.?)))
        {
            return error.InvalidPlatform;
        }
        return .{
            .os = os,
            .architecture = architecture,
            .variant = self.variant,
        };
    }
};

const CopyArgs = struct {
    source: []const u8,
    destination: []const u8,
    source_options: EndpointOptions,
    destination_options: EndpointOptions,
    graph: oci.copy.Options,
};

const InspectArgs = struct {
    source: []const u8,
    endpoint: EndpointOptions,
    options: oci.registry.InspectOptions,
};

const TagsArgs = struct {
    source: []const u8,
    endpoint: EndpointOptions,
};

const PinArgs = struct {
    source: []const u8,
    endpoint: EndpointOptions,
    json: bool,
};

const UnpackArgs = struct {
    source: []const u8,
    destination: []const u8,
    platform: oci.model.Platform,
    rootless: bool,
    force: bool,
};

const RepackArgs = struct {
    target: []const u8,
    bundle: []const u8,
    compression: oci.repack.Compression,
};

const ConfigArgs = struct {
    source: []const u8,
    platform: oci.model.Platform,
};

pub fn run(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: []const []const u8,
) u8 {
    if (args.len == 0) return fail("{s}", .{usage});
    if (isHelp(args[0])) {
        std.debug.print("{s}", .{usage});
        return 0;
    }
    if (std.mem.eql(u8, args[0], "copy")) {
        const parsed = parseCopy(args[1..]) catch |err|
            return argumentFailure("copy", err);
        return runCopy(allocator, io, environ, parsed);
    }
    if (std.mem.eql(u8, args[0], "inspect")) {
        const parsed = parseInspect(args[1..]) catch |err|
            return argumentFailure("inspect", err);
        return runInspect(allocator, io, environ, parsed);
    }
    if (std.mem.eql(u8, args[0], "list-tags")) {
        const parsed = parseTags(args[1..]) catch |err|
            return argumentFailure("list-tags", err);
        return runTags(allocator, io, environ, parsed);
    }
    if (std.mem.eql(u8, args[0], "pin")) {
        const parsed = parsePin(args[1..]) catch |err|
            return argumentFailure("pin", err);
        return runPin(allocator, io, environ, parsed);
    }
    if (std.mem.eql(u8, args[0], "unpack")) {
        const parsed = parseUnpack(args[1..]) catch |err|
            return argumentFailure("unpack", err);
        return runUnpack(allocator, io, parsed);
    }
    if (std.mem.eql(u8, args[0], "repack")) {
        const parsed = parseRepack(args[1..]) catch |err|
            return argumentFailure("repack", err);
        return runRepack(allocator, io, parsed);
    }
    if (std.mem.eql(u8, args[0], "config")) {
        const parsed = parseConfig(args[1..]) catch |err|
            return argumentFailure("config", err);
        return runConfig(allocator, io, parsed);
    }
    return fail("miz oci: unknown subcommand '{s}'\n\n{s}", .{ args[0], usage });
}

fn runConfig(
    allocator: std.mem.Allocator,
    io: Io,
    args: ConfigArgs,
) u8 {
    const parsed = oci.reference.parse(args.source, .source) catch |err|
        return fail("miz oci config: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    const source_ref = switch (parsed) {
        .layout => |value| value,
        .registry => return fail(
            "miz oci config: source must be a local OCI layout: '{s}'",
            .{args.source},
        ),
    };
    var source = oci.layout.Source.init(io, allocator, source_ref.path);
    var resolved = oci.image_resolver.resolveLayout(
        allocator,
        &source,
        source_ref,
        .{ .platform = args.platform },
    ) catch |err| return fail(
        "miz oci config: '{s}' failed: {s}",
        .{ args.source, @errorName(err) },
    );
    defer resolved.deinit();
    writeLine(io, resolved.config_bytes) catch |err|
        return fail("miz oci config: failed to write output: {s}", .{@errorName(err)});
    return 0;
}

fn runRepack(
    allocator: std.mem.Allocator,
    io: Io,
    args: RepackArgs,
) u8 {
    const parsed = oci.reference.parse(args.target, .destination) catch |err|
        return fail("miz oci repack: invalid target '{s}': {s}", .{ args.target, @errorName(err) });
    const target = switch (parsed) {
        .layout => |value| value,
        .registry => return fail(
            "miz oci repack: target must be a local OCI layout: '{s}'",
            .{args.target},
        ),
    };
    const result = oci.repack.repackLayout(
        allocator,
        io,
        target,
        args.bundle,
        .{ .compression = args.compression },
    ) catch |err| return fail(
        "miz oci repack: '{s}' to '{s}' failed: {s}",
        .{ args.bundle, args.target, @errorName(err) },
    );
    writeLine(io, result.digest()) catch |err|
        return fail("miz oci repack: failed to write output: {s}", .{@errorName(err)});
    return 0;
}

fn runUnpack(
    allocator: std.mem.Allocator,
    io: Io,
    args: UnpackArgs,
) u8 {
    const source = oci.reference.parse(args.source, .source) catch |err|
        return fail("miz oci unpack: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    const local = switch (source) {
        .layout => |value| value,
        .registry => return fail(
            "miz oci unpack: source must be a local OCI layout: '{s}'",
            .{args.source},
        ),
    };
    const result = oci.bundle.unpackLayout(
        allocator,
        io,
        args.source,
        local,
        args.destination,
        .{
            .platform = args.platform,
            .preserve_ownership = !args.rootless,
            .force = args.force,
        },
    ) catch |err| return fail(
        "miz oci unpack: '{s}' to '{s}' failed: {s}",
        .{ args.source, args.destination, @errorName(err) },
    );
    if (result.cleanup_warning) {
        std.debug.print(
            "miz oci unpack: warning: replaced bundle was left at a hidden staging path because cleanup failed\n",
            .{},
        );
    }
    writeLine(io, result.digest()) catch |err|
        return fail("miz oci unpack: failed to write output: {s}", .{@errorName(err)});
    return 0;
}

fn runCopy(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: CopyArgs,
) u8 {
    const source = oci.reference.parse(args.source, .source) catch |err|
        return fail("miz oci copy: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    const destination = oci.reference.parse(args.destination, .destination) catch |err|
        return fail("miz oci copy: invalid destination '{s}': {s}", .{ args.destination, @errorName(err) });
    validateEndpoint(source, args.source_options) catch |err|
        return argumentFailure("copy", err);
    validateEndpoint(destination, args.destination_options) catch |err|
        return argumentFailure("copy", err);

    return switch (source) {
        .layout => |local_source| switch (destination) {
            .layout => |local_destination| finishCopy(
                allocator,
                io,
                oci.copy.localToLocal(
                    io,
                    allocator,
                    local_source,
                    local_destination,
                    args.graph,
                ) catch |err| return failCopy(args, err),
            ),
            .registry => |remote_destination| copyLayoutToRegistry(
                allocator,
                io,
                environ,
                args,
                local_source,
                remote_destination,
            ),
        },
        .registry => |remote_source| switch (destination) {
            .layout => |local_destination| copyRegistryToLayout(
                allocator,
                io,
                environ,
                args,
                remote_source,
                local_destination,
            ),
            .registry => |remote_destination| copyRegistryToRegistry(
                allocator,
                io,
                environ,
                args,
                remote_source,
                remote_destination,
            ),
        },
    };
}

fn copyLayoutToRegistry(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: CopyArgs,
    source: oci.reference.LayoutReference,
    destination: oci.reference.RegistryReference,
) u8 {
    var target = oci.registry.Destination.init(
        io,
        allocator,
        environ,
        destination,
        args.destination_options.registry(),
    ) catch |err| return failCopy(args, err);
    defer target.deinit();
    const result = target.copyFromLayout(source, args.graph) catch |err| {
        if (target.lastError()) |status| {
            return failRegistry("copy", args.destination, status, err);
        }
        return failCopy(args, err);
    };
    return finishCopy(allocator, io, result);
}

fn copyRegistryToLayout(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: CopyArgs,
    source: oci.reference.RegistryReference,
    destination: oci.reference.LayoutReference,
) u8 {
    var client = oci.registry.Source.init(
        io,
        allocator,
        environ,
        source,
        args.source_options.registry(),
    ) catch |err| return failCopy(args, err);
    defer client.deinit();
    const result = client.copyToLayout(
        source,
        destination,
        args.graph,
    ) catch |err| {
        if (client.lastError()) |status| {
            return failRegistry("copy", args.source, status, err);
        }
        return failCopy(args, err);
    };
    return finishCopy(allocator, io, result);
}

fn copyRegistryToRegistry(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: CopyArgs,
    source: oci.reference.RegistryReference,
    destination: oci.reference.RegistryReference,
) u8 {
    var client = oci.registry.Source.init(
        io,
        allocator,
        environ,
        source,
        args.source_options.registry(),
    ) catch |err| return failCopy(args, err);
    defer client.deinit();
    var target = oci.registry.Destination.init(
        io,
        allocator,
        environ,
        destination,
        args.destination_options.registry(),
    ) catch |err| return failCopy(args, err);
    defer target.deinit();
    const result = client.copyToDestination(
        source,
        &target,
        args.graph,
    ) catch |err| {
        if (target.lastError()) |status| {
            return failRegistry("copy", args.destination, status, err);
        }
        if (client.lastError()) |status| {
            return failRegistry("copy", args.source, status, err);
        }
        return failCopy(args, err);
    };
    return finishCopy(allocator, io, result);
}

fn finishCopy(
    allocator: std.mem.Allocator,
    io: Io,
    copy_result: oci.copy.Result,
) u8 {
    var result = copy_result;
    defer result.deinit(allocator);
    writeLine(io, result.root.digest) catch |err|
        return fail("miz oci copy: failed to write output: {s}", .{@errorName(err)});
    return 0;
}

fn failCopy(args: CopyArgs, err: anyerror) u8 {
    return fail(
        "miz oci copy: '{s}' to '{s}' failed: {s}",
        .{ args.source, args.destination, @errorName(err) },
    );
}

fn runInspect(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: InspectArgs,
) u8 {
    const source = oci.reference.parse(args.source, .source) catch |err|
        return fail("miz oci inspect: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    validateEndpoint(source, args.endpoint) catch |err|
        return argumentFailure("inspect", err);
    return switch (source) {
        .registry => |remote| inspectRegistry(
            allocator,
            io,
            environ,
            args,
            remote,
        ),
        .layout => |local| blk: {
            var client = oci.layout.Source.init(io, allocator, local.path);
            var resolved = client.resolve(local) catch |err|
                return failInspect(args.source, err);
            defer resolved.deinit();
            const result = oci.registry.inspectResolved(
                allocator,
                client.asTransport(),
                args.source,
                resolved.descriptor,
                args.options,
            ) catch |err| return failInspect(args.source, err);
            break :blk finishInspect(allocator, io, result);
        },
    };
}

fn inspectRegistry(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: InspectArgs,
    source: oci.reference.RegistryReference,
) u8 {
    var client = oci.registry.Source.init(
        io,
        allocator,
        environ,
        source,
        args.endpoint.registry(),
    ) catch |err| return failInspect(args.source, err);
    defer client.deinit();
    const result = client.inspect(source, args.options) catch |err| {
        if (client.lastError()) |status| {
            return failRegistry("inspect", args.source, status, err);
        }
        return failInspect(args.source, err);
    };
    return finishInspect(allocator, io, result);
}

fn finishInspect(
    allocator: std.mem.Allocator,
    io: Io,
    inspect_result: oci.registry.InspectResult,
) u8 {
    var result = inspect_result;
    defer result.deinit();
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const output = inspectOutput(
        arena_state.allocator(),
        result,
    ) catch |err| return fail(
        "miz oci inspect: failed to format output: {s}",
        .{@errorName(err)},
    );
    writeJson(io, output) catch |err|
        return fail("miz oci inspect: failed to write output: {s}", .{@errorName(err)});
    return 0;
}

fn failInspect(source: []const u8, err: anyerror) u8 {
    return fail(
        "miz oci inspect: '{s}' failed: {s}",
        .{ source, @errorName(err) },
    );
}

fn runTags(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: TagsArgs,
) u8 {
    const parsed = oci.reference.parse(args.source, .list_tags) catch |err|
        return fail("miz oci list-tags: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    const source = switch (parsed) {
        .registry => |value| value,
        .layout => unreachable,
    };
    var client = oci.registry.Source.init(
        io,
        allocator,
        environ,
        source,
        args.endpoint.registry(),
    ) catch |err| return fail(
        "miz oci list-tags: '{s}' failed: {s}",
        .{ args.source, @errorName(err) },
    );
    defer client.deinit();
    var tags = client.listTags(source) catch |err| {
        if (client.lastError()) |status| {
            return failRegistry("list-tags", args.source, status, err);
        }
        return fail(
            "miz oci list-tags: '{s}' failed: {s}",
            .{ args.source, @errorName(err) },
        );
    };
    defer tags.deinit();
    writeJson(io, .{
        .schema_version = @as(u32, 1),
        .repository = args.source,
        .tags = tags.tags,
    }) catch |err| return fail(
        "miz oci list-tags: failed to write output: {s}",
        .{@errorName(err)},
    );
    return 0;
}

fn runPin(
    allocator: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    args: PinArgs,
) u8 {
    const parsed = oci.reference.parse(args.source, .source) catch |err|
        return fail("miz oci pin: invalid source '{s}': {s}", .{ args.source, @errorName(err) });
    const source = switch (parsed) {
        .registry => |value| value,
        .layout => return fail(
            "miz oci pin: source must be a registry reference: '{s}'",
            .{args.source},
        ),
    };
    var client = oci.registry.Source.init(
        io,
        allocator,
        environ,
        source,
        args.endpoint.registry(),
    ) catch |err| return fail(
        "miz oci pin: '{s}' failed: {s}",
        .{ args.source, @errorName(err) },
    );
    defer client.deinit();
    var result = client.pin(source) catch |err| {
        if (client.lastError()) |status| {
            return failRegistry("pin", args.source, status, err);
        }
        return fail("miz oci pin: '{s}' failed: {s}", .{ args.source, @errorName(err) });
    };
    defer result.deinit();
    if (!args.json) {
        writeLine(io, result.reference) catch |err|
            return fail("miz oci pin: failed to write output: {s}", .{@errorName(err)});
        return 0;
    }
    writeJson(io, .{
        .schema_version = @as(u32, 1),
        .requested = args.source,
        .reference = result.reference,
        .media_type = result.media_type,
        .digest = result.digest,
        .size = result.size,
        .kind = result.kind,
        .platform = if (result.platform) |value| JsonPlatform{
            .os = value.os,
            .architecture = value.architecture,
            .variant = value.variant,
        } else null,
    }) catch |err| return fail(
        "miz oci pin: failed to write output: {s}",
        .{@errorName(err)},
    );
    return 0;
}

fn parsePin(args: []const []const u8) ParseError!PinArgs {
    var endpoint: EndpointOptions = .{};
    var source: ?[]const u8 = null;
    var json = false;
    var json_set = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--authfile")) {
            endpoint.authfile = try uniqueValue(args, &i, endpoint.authfile);
        } else if (std.mem.eql(u8, argument, "--tls-ca")) {
            endpoint.tls_ca = try uniqueValue(args, &i, endpoint.tls_ca);
        } else if (std.mem.eql(u8, argument, "--plain-http")) {
            try setPlainHttp(&endpoint);
        } else if (std.mem.eql(u8, argument, "--json")) {
            if (json_set) return error.DuplicateOption;
            json = true;
            json_set = true;
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (source == null) {
            source = argument;
        } else {
            return error.InvalidArguments;
        }
    }
    return .{
        .source = source orelse return error.InvalidArguments,
        .endpoint = endpoint,
        .json = json,
    };
}

fn parseCopy(args: []const []const u8) ParseError!CopyArgs {
    var source_options: EndpointOptions = .{};
    var destination_options: EndpointOptions = .{};
    var platform: PlatformOptions = .{};
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--all")) {
            if (platform.all_set) return error.DuplicateOption;
            platform.all = true;
            platform.all_set = true;
        } else if (std.mem.eql(u8, argument, "--override-os")) {
            platform.os = try uniqueValue(args, &i, platform.os);
        } else if (std.mem.eql(u8, argument, "--override-arch")) {
            platform.architecture = try uniqueValue(args, &i, platform.architecture);
        } else if (std.mem.eql(u8, argument, "--override-variant")) {
            platform.variant = try uniqueValue(args, &i, platform.variant);
        } else if (std.mem.eql(u8, argument, "--src-authfile")) {
            source_options.authfile = try uniqueValue(args, &i, source_options.authfile);
        } else if (std.mem.eql(u8, argument, "--dest-authfile")) {
            destination_options.authfile = try uniqueValue(args, &i, destination_options.authfile);
        } else if (std.mem.eql(u8, argument, "--src-tls-ca")) {
            source_options.tls_ca = try uniqueValue(args, &i, source_options.tls_ca);
        } else if (std.mem.eql(u8, argument, "--dest-tls-ca")) {
            destination_options.tls_ca = try uniqueValue(args, &i, destination_options.tls_ca);
        } else if (std.mem.eql(u8, argument, "--src-plain-http")) {
            try setPlainHttp(&source_options);
        } else if (std.mem.eql(u8, argument, "--dest-plain-http")) {
            try setPlainHttp(&destination_options);
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (positional_count < positional.len) {
            positional[positional_count] = argument;
            positional_count += 1;
        } else {
            return error.InvalidArguments;
        }
    }
    if (positional_count != positional.len) return error.InvalidArguments;
    return .{
        .source = positional[0],
        .destination = positional[1],
        .source_options = source_options,
        .destination_options = destination_options,
        .graph = try platform.graph(),
    };
}

fn parseInspect(args: []const []const u8) ParseError!InspectArgs {
    var endpoint: EndpointOptions = .{};
    var platform: PlatformOptions = .{};
    var source: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--all")) {
            if (platform.all_set) return error.DuplicateOption;
            platform.all = true;
            platform.all_set = true;
        } else if (std.mem.eql(u8, argument, "--override-os")) {
            platform.os = try uniqueValue(args, &i, platform.os);
        } else if (std.mem.eql(u8, argument, "--override-arch")) {
            platform.architecture = try uniqueValue(args, &i, platform.architecture);
        } else if (std.mem.eql(u8, argument, "--override-variant")) {
            platform.variant = try uniqueValue(args, &i, platform.variant);
        } else if (std.mem.eql(u8, argument, "--authfile")) {
            endpoint.authfile = try uniqueValue(args, &i, endpoint.authfile);
        } else if (std.mem.eql(u8, argument, "--tls-ca")) {
            endpoint.tls_ca = try uniqueValue(args, &i, endpoint.tls_ca);
        } else if (std.mem.eql(u8, argument, "--plain-http")) {
            try setPlainHttp(&endpoint);
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (source == null) {
            source = argument;
        } else {
            return error.InvalidArguments;
        }
    }
    return .{
        .source = source orelse return error.InvalidArguments,
        .endpoint = endpoint,
        .options = try platform.inspect(),
    };
}

fn parseTags(args: []const []const u8) ParseError!TagsArgs {
    var endpoint: EndpointOptions = .{};
    var source: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--authfile")) {
            endpoint.authfile = try uniqueValue(args, &i, endpoint.authfile);
        } else if (std.mem.eql(u8, argument, "--tls-ca")) {
            endpoint.tls_ca = try uniqueValue(args, &i, endpoint.tls_ca);
        } else if (std.mem.eql(u8, argument, "--plain-http")) {
            try setPlainHttp(&endpoint);
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (source == null) {
            source = argument;
        } else {
            return error.InvalidArguments;
        }
    }
    return .{ .source = source orelse return error.InvalidArguments, .endpoint = endpoint };
}

fn parseUnpack(args: []const []const u8) ParseError!UnpackArgs {
    var source: ?[]const u8 = null;
    var destination: ?[]const u8 = null;
    var platform: PlatformOptions = .{};
    var rootless = false;
    var rootless_set = false;
    var force = false;
    var force_set = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--image")) {
            source = try uniqueValue(args, &i, source);
        } else if (std.mem.eql(u8, argument, "--override-os")) {
            platform.os = try uniqueValue(args, &i, platform.os);
        } else if (std.mem.eql(u8, argument, "--override-arch")) {
            platform.architecture = try uniqueValue(args, &i, platform.architecture);
        } else if (std.mem.eql(u8, argument, "--override-variant")) {
            platform.variant = try uniqueValue(args, &i, platform.variant);
        } else if (std.mem.eql(u8, argument, "--rootless")) {
            if (rootless_set) return error.DuplicateOption;
            rootless = true;
            rootless_set = true;
        } else if (std.mem.eql(u8, argument, "--force")) {
            if (force_set) return error.DuplicateOption;
            force = true;
            force_set = true;
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (destination == null) {
            destination = argument;
        } else {
            return error.InvalidArguments;
        }
    }
    return .{
        .source = source orelse return error.InvalidArguments,
        .destination = destination orelse return error.InvalidArguments,
        .platform = try platform.selected(),
        .rootless = rootless,
        .force = force,
    };
}

fn parseRepack(args: []const []const u8) ParseError!RepackArgs {
    var target: ?[]const u8 = null;
    var bundle_path: ?[]const u8 = null;
    var compression_value: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--image")) {
            target = try uniqueValue(args, &i, target);
        } else if (std.mem.eql(u8, argument, "--compression")) {
            compression_value = try uniqueValue(args, &i, compression_value);
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.InvalidOption;
        } else if (bundle_path == null) {
            bundle_path = argument;
        } else {
            return error.InvalidArguments;
        }
    }
    return .{
        .target = target orelse return error.InvalidArguments,
        .bundle = bundle_path orelse return error.InvalidArguments,
        .compression = if (compression_value) |value|
            std.meta.stringToEnum(oci.repack.Compression, value) orelse
                return error.InvalidArguments
        else
            .same,
    };
}

fn parseConfig(args: []const []const u8) ParseError!ConfigArgs {
    var source: ?[]const u8 = null;
    var platform: PlatformOptions = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--image")) {
            source = try uniqueValue(args, &i, source);
        } else if (std.mem.eql(u8, argument, "--override-os")) {
            platform.os = try uniqueValue(args, &i, platform.os);
        } else if (std.mem.eql(u8, argument, "--override-arch")) {
            platform.architecture = try uniqueValue(args, &i, platform.architecture);
        } else if (std.mem.eql(u8, argument, "--override-variant")) {
            platform.variant = try uniqueValue(args, &i, platform.variant);
        } else {
            return if (std.mem.startsWith(u8, argument, "-"))
                error.InvalidOption
            else
                error.InvalidArguments;
        }
    }
    return .{
        .source = source orelse return error.InvalidArguments,
        .platform = try platform.selected(),
    };
}

fn uniqueValue(
    args: []const []const u8,
    index: *usize,
    current: ?[]const u8,
) ParseError![]const u8 {
    if (current != null) return error.DuplicateOption;
    index.* += 1;
    if (index.* >= args.len) return error.MissingOptionValue;
    if (std.mem.startsWith(u8, args[index.*], "-")) return error.MissingOptionValue;
    return args[index.*];
}

fn setPlainHttp(endpoint: *EndpointOptions) ParseError!void {
    if (endpoint.plain_http_set) return error.DuplicateOption;
    endpoint.plain_http = true;
    endpoint.plain_http_set = true;
}

fn validateEndpoint(
    reference: oci.reference.Reference,
    options: EndpointOptions,
) ParseError!void {
    if (reference == .layout and options.any()) return error.InvalidTransportOption;
}

const JsonPlatform = struct {
    os: []const u8,
    architecture: []const u8,
    variant: ?[]const u8,
};

const JsonDescriptor = struct {
    media_type: ?[]const u8,
    digest: []const u8,
    size: u64,
    annotations: ?std.json.Value,
    platform: ?JsonPlatform,
};

const JsonNode = struct {
    media_type: ?[]const u8,
    digest: []const u8,
    size: u64,
    kind: oci.registry.InspectKind,
    annotations: ?std.json.Value,
    platform: ?JsonPlatform,
    config: ?JsonDescriptor,
    layers: []JsonDescriptor,
    manifests: []JsonNode,
};

const JsonInspect = struct {
    schema_version: u32,
    reference: []const u8,
    media_type: ?[]const u8,
    digest: []const u8,
    size: u64,
    kind: oci.registry.InspectKind,
    annotations: ?std.json.Value,
    platform: ?JsonPlatform,
    config: ?JsonDescriptor,
    layers: []JsonDescriptor,
    manifests: []JsonNode,
};

fn inspectOutput(
    allocator: std.mem.Allocator,
    result: oci.registry.InspectResult,
) !JsonInspect {
    const root = try jsonNode(allocator, result.root);
    return .{
        .schema_version = result.schema_version,
        .reference = result.reference,
        .media_type = root.media_type,
        .digest = root.digest,
        .size = root.size,
        .kind = root.kind,
        .annotations = root.annotations,
        .platform = root.platform,
        .config = root.config,
        .layers = root.layers,
        .manifests = root.manifests,
    };
}

fn jsonNode(
    allocator: std.mem.Allocator,
    node: oci.registry.InspectNode,
) !JsonNode {
    const layers = try allocator.alloc(JsonDescriptor, node.layers.len);
    for (node.layers, 0..) |descriptor, index| {
        layers[index] = try jsonDescriptor(allocator, descriptor);
    }
    const manifests = try allocator.alloc(JsonNode, node.manifests.len);
    for (node.manifests, 0..) |child, index| {
        manifests[index] = try jsonNode(allocator, child);
    }
    const descriptor = try jsonDescriptor(allocator, node.descriptor);
    return .{
        .media_type = descriptor.media_type,
        .digest = descriptor.digest,
        .size = descriptor.size,
        .kind = node.kind,
        .annotations = descriptor.annotations,
        .platform = descriptor.platform,
        .config = if (node.config) |config_descriptor|
            try jsonDescriptor(allocator, config_descriptor)
        else
            null,
        .layers = layers,
        .manifests = manifests,
    };
}

fn jsonDescriptor(
    allocator: std.mem.Allocator,
    descriptor: oci.registry.Descriptor,
) !JsonDescriptor {
    const annotations = if (descriptor.annotations_json) |bytes|
        try std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{})
    else
        null;
    return .{
        .media_type = descriptor.media_type,
        .digest = descriptor.digest,
        .size = descriptor.size,
        .annotations = annotations,
        .platform = if (descriptor.platform) |platform| .{
            .os = platform.os,
            .architecture = platform.architecture,
            .variant = platform.variant,
        } else null,
    };
}

fn writeJson(io: Io, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try std.json.Stringify.value(value, .{}, writer);
    try writer.writeByte('\n');
    try writer.flush();
}

fn writeLine(io: Io, value: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print("{s}\n", .{value});
    try writer.flush();
}

fn validPlatformComponent(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '_' and byte != '.' and byte != '-')
        {
            return false;
        }
    }
    return true;
}

fn hostOs() []const u8 {
    return switch (builtin.os.tag) {
        .macos => "darwin",
        else => @tagName(builtin.os.tag),
    };
}

fn hostArchitecture() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    };
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or
        std.mem.eql(u8, value, "-h") or
        std.mem.eql(u8, value, "help");
}

fn argumentFailure(subcommand: []const u8, err: anyerror) u8 {
    return fail(
        "miz oci {s}: invalid arguments: {s}\n\n{s}",
        .{ subcommand, @errorName(err), usage },
    );
}

fn failRegistry(
    operation: []const u8,
    reference: []const u8,
    status: *const oci.registry.StatusError,
    err: anyerror,
) u8 {
    if (status.code) |code| {
        return fail(
            "miz oci {s}: '{s}' failed: HTTP {d} {s} ({s})",
            .{ operation, reference, status.status, code, @errorName(err) },
        );
    }
    return fail(
        "miz oci {s}: '{s}' failed: HTTP {d} ({s})",
        .{ operation, reference, status.status, @errorName(err) },
    );
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "copy parser accepts documented options and rejects conflicts" {
    const parsed = try parseCopy(&.{
        "--override-os",
        "linux",
        "--override-arch",
        "arm64",
        "--override-variant",
        "v8",
        "--src-authfile",
        "source.json",
        "--dest-tls-ca",
        "ca.pem",
        "--src-plain-http",
        "docker://registry.example/team/source:latest",
        "oci:layout:copied",
    });
    try std.testing.expectEqualStrings("source.json", parsed.source_options.authfile.?);
    try std.testing.expectEqualStrings("ca.pem", parsed.destination_options.tls_ca.?);
    try std.testing.expect(parsed.source_options.plain_http);
    const selected = parsed.graph.mode.selected;
    try std.testing.expectEqualStrings("linux", selected.os);
    try std.testing.expectEqualStrings("arm64", selected.architecture);
    try std.testing.expectEqualStrings("v8", selected.variant.?);
    try std.testing.expectError(error.ConflictingPlatformOptions, parseCopy(&.{
        "--all",
        "--override-arch",
        "amd64",
        "oci:source:latest",
        "oci:destination:latest",
    }));
    try std.testing.expectError(error.DuplicateOption, parseCopy(&.{
        "--src-plain-http",
        "--src-plain-http",
        "docker://registry.example/source:latest",
        "oci:destination:latest",
    }));
}

test "inspect and list-tags parsers enforce their option sets" {
    const inspected = try parseInspect(&.{
        "--all",
        "--authfile",
        "auth.json",
        "docker://registry.example/team/image:latest",
    });
    try std.testing.expect(inspected.options.mode == .all);
    try std.testing.expectEqualStrings("auth.json", inspected.endpoint.authfile.?);
    try std.testing.expectError(error.InvalidOption, parseTags(&.{
        "--all",
        "docker://registry.example/team/image",
    }));
    const local = try oci.reference.parse("oci:layout:latest", .source);
    try std.testing.expectError(
        error.InvalidTransportOption,
        validateEndpoint(local, .{ .plain_http = true, .plain_http_set = true }),
    );
}

test "pin parser accepts registry options and refuses platform selection" {
    const parsed = try parsePin(&.{
        "--authfile",
        "auth.json",
        "--json",
        "docker://registry.example/team/image:latest",
    });
    try std.testing.expectEqualStrings("docker://registry.example/team/image:latest", parsed.source);
    try std.testing.expectEqualStrings("auth.json", parsed.endpoint.authfile.?);
    try std.testing.expect(parsed.json);
    try std.testing.expectError(error.DuplicateOption, parsePin(&.{
        "--json",
        "--json",
        "docker://registry.example/team/image:latest",
    }));
    try std.testing.expectError(error.InvalidOption, parsePin(&.{
        "--all",
        "docker://registry.example/team/image:latest",
    }));
    try std.testing.expectError(error.InvalidArguments, parsePin(&.{"--plain-http"}));
}

test "unpack parser accepts image platform and rootless options" {
    const parsed = try parseUnpack(&.{
        "--image",
        "oci:layout:latest",
        "--override-os",
        "linux",
        "--override-arch",
        "arm64",
        "--override-variant",
        "v8",
        "--rootless",
        "bundle",
    });
    try std.testing.expectEqualStrings("oci:layout:latest", parsed.source);
    try std.testing.expectEqualStrings("bundle", parsed.destination);
    try std.testing.expectEqualStrings("linux", parsed.platform.os);
    try std.testing.expectEqualStrings("arm64", parsed.platform.architecture);
    try std.testing.expectEqualStrings("v8", parsed.platform.variant.?);
    try std.testing.expect(parsed.rootless);
    try std.testing.expectError(error.InvalidArguments, parseUnpack(&.{
        "bundle",
    }));
}

test "repack parser requires target image and bundle" {
    const parsed = try parseRepack(&.{
        "--image",
        "oci:layout:edited",
        "bundle",
    });
    try std.testing.expectEqualStrings("oci:layout:edited", parsed.target);
    try std.testing.expectEqualStrings("bundle", parsed.bundle);
    try std.testing.expectError(error.InvalidArguments, parseRepack(&.{
        "--image",
        "oci:layout:edited",
    }));
}

test "config parser accepts image and explicit platform" {
    const parsed = try parseConfig(&.{
        "--image",
        "oci:layout:latest",
        "--override-os",
        "linux",
        "--override-arch",
        "amd64",
    });
    try std.testing.expectEqualStrings("oci:layout:latest", parsed.source);
    try std.testing.expectEqualStrings("linux", parsed.platform.os);
    try std.testing.expectEqualStrings("amd64", parsed.platform.architecture);
    try std.testing.expectError(error.InvalidArguments, parseConfig(&.{
        "oci:layout:latest",
    }));
}

test "inspect JSON formatting emits annotation objects deterministically" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const annotations = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"org.example\":\"kept\"}",
        .{},
    );
    const output = JsonInspect{
        .schema_version = 1,
        .reference = "oci:layout:latest",
        .media_type = oci.model.media_type_oci_manifest,
        .digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .size = 42,
        .kind = .manifest,
        .annotations = annotations,
        .platform = .{ .os = "linux", .architecture = "amd64", .variant = null },
        .config = null,
        .layers = &.{},
        .manifests = &.{},
    };
    var buffer: [2048]u8 = undefined;
    var writer = Io.Writer.fixed(&buffer);
    try std.json.Stringify.value(output, .{}, &writer);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"reference\":\"oci:layout:latest\",\"media_type\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size\":42,\"kind\":\"manifest\",\"annotations\":{\"org.example\":\"kept\"},\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":null},\"config\":null,\"layers\":[],\"manifests\":[]}",
        writer.buffered(),
    );
}
