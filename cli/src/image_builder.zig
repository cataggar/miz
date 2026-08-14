//! Host-native entry point used by the exported `std.Build` image helper.

const std = @import("std");
const builtin = @import("builtin");
const customization_loader = @import("customization_loader.zig");
const zvmi = @import("zvmi");

/// What `--container` named, before the run has decided anything about it.
///
/// A local path and a registry reference are not the same kind of thing --
/// one can be hashed and checked for overlap with the output, the other
/// cannot -- so they are distinguished at parse time rather than by asking
/// the same string different questions later.
const ContainerArg = union(enum) {
    host_path: []const u8,
    registry: RegistryArg,
};

/// A declared registry image, as the command line stated it.
///
/// There is deliberately no `--registry-authfile` here. An authfile is a
/// discovery mechanism, and a customize run does not discover: the request
/// states its credential so the plan hash can cover where the password comes
/// from, and a `~/.docker/config.json` is exactly the ambient dependency that
/// makes a build mean different things on different machines. `zvmi oci pull`
/// still honours one, because a person at a terminal expects their login to
/// work.
const RegistryArg = struct {
    reference: []const u8,
    username: ?[]const u8 = null,
    password: ?zvmi.customize.CredentialSource = null,
    tls_ca: ?[]const u8 = null,
    plain_http: bool = false,
    signature_key: ?[]const u8 = null,

    fn access(self: RegistryArg) !zvmi.customize.RegistryAccess {
        // Both halves or neither: a user name with no password names an
        // identity that cannot authenticate, and a password with no user name
        // has no identity to authenticate as.
        const credential: ?zvmi.customize.BasicCredential = if (self.username) |name| .{
            .username = name,
            .password = self.password orelse return error.IncompleteRegistryCredential,
        } else if (self.password != null) return error.IncompleteRegistryCredential else null;
        return .{
            .credential = credential,
            .tls_ca = self.tls_ca,
            .plain_http = self.plain_http,
        };
    }

    /// The key is named by path and not read here. `parseArgs` runs before
    /// the run has decided it may read trust material at all, so reading it
    /// now would be reading a file the capability check has not yet allowed.
    fn signature(self: RegistryArg) ?zvmi.customize.RegistrySignaturePolicy {
        const path = self.signature_key orelse return null;
        return .{ .key = .{ .host_path = path } };
    }
};

const ParsedArgs = struct {
    api_version: u32 = zvmi.customize.current_api_version,
    architecture: zvmi.customize.Architecture,
    iso_path: []const u8,
    container: ContainerArg,
    rootfs_path: []const u8,
    bundle_output_path: []const u8,
    image_basename: []const u8,
    format: zvmi.customize.OutputFormat,
    size: u64,
    generation: zvmi.azure.Generation = .gen2,
    skip_iso_rootfs: bool = false,
    esp_size: u64 = zvmi.build_image.default_esp_size,
    ext4_label: []const u8 = "rootfs",
    root_filesystem: zvmi.layout.FilesystemKind = .ext4,
    verity: bool = false,
    extra_kernel_options: []const u8 = "",
    boot_mode: zvmi.bootconfig.BootMode = .bls_only,
    uki: zvmi.customize.UkiOptions = .{},
    uki_signing: ?zvmi.customize.UkiSigningPolicy = null,
    customization_path: ?[]const u8 = null,
    customization_source_paths: []const []const u8 = &.{},
    seed: zvmi.customize.Seed,
    source_date_epoch: u64,
    limits: zvmi.limits.ImportLimits = .{},
    preflight_only: bool = false,
    reuse_success: bool = false,
    verbose: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    var args = parseArgs(arena, argv[1..]) catch |err| {
        std.debug.print("zvmi-image-builder: invalid arguments: {t}\n", .{err});
        std.process.exit(2);
    };
    // Resolved here rather than left to `validate`, because a person holding
    // a tag has to be told the digest it named to be able to commit to it.
    // Printed on stderr, not just used: a build that silently followed a tag
    // would be the ambiguity the digest requirement exists to remove.
    if (args.container == .registry) {
        args.container.registry.reference = pinIfTagged(
            arena,
            init.io,
            init.minimal.environ,
            args.container.registry,
        ) catch |err| {
            std.debug.print(
                "zvmi-image-builder: cannot pin '{s}': {t}\n",
                .{ args.container.registry.reference, err },
            );
            std.process.exit(1);
        };
    }
    if (!isBasename(args.image_basename) or isReservedBasename(args.image_basename)) {
        std.debug.print("zvmi-image-builder: image output must be a non-reserved basename\n", .{});
        std.process.exit(2);
    }
    const overlaps_source = pathsOverlapCanonically(arena, init.io, args.bundle_output_path, args.iso_path) catch |err| {
        std.debug.print("zvmi-image-builder: cannot isolate result bundle from ISO source: {t}\n", .{err});
        std.process.exit(1);
    } or switch (args.container) {
        // A registry image is not a path on this machine, so there is nothing
        // for the output to overlap with.
        .registry => false,
        .host_path => |path| pathsOverlapCanonically(arena, init.io, args.bundle_output_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result bundle from container source: {t}\n", .{err});
            std.process.exit(1);
        },
    };
    if (overlaps_source) {
        std.debug.print("zvmi-image-builder: result bundle and source paths must be distinct\n", .{});
        std.process.exit(2);
    }
    if (args.customization_path) |path| {
        if (pathsOverlapCanonically(arena, init.io, args.bundle_output_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result bundle from customization config: {t}\n", .{err});
            std.process.exit(1);
        }) {
            std.debug.print("zvmi-image-builder: result bundle and customization config must be distinct\n", .{});
            std.process.exit(2);
        }
    }
    for (args.customization_source_paths) |path| {
        if (pathsOverlapCanonically(arena, init.io, args.bundle_output_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result bundle from customization source: {t}\n", .{err});
            std.process.exit(1);
        }) {
            std.debug.print("zvmi-image-builder: result bundle and customization sources must be distinct\n", .{});
            std.process.exit(2);
        }
    }
    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{args.bundle_output_path});
    const lock_overlaps_source = pathsOverlapCanonically(arena, init.io, lock_path, args.iso_path) catch |err| {
        std.debug.print("zvmi-image-builder: cannot isolate result lock from ISO source: {t}\n", .{err});
        std.process.exit(1);
    } or switch (args.container) {
        .registry => false,
        .host_path => |path| pathsOverlapCanonically(arena, init.io, lock_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result lock from container source: {t}\n", .{err});
            std.process.exit(1);
        },
    };
    if (lock_overlaps_source) {
        std.debug.print("zvmi-image-builder: result lock and source paths must be distinct\n", .{});
        std.process.exit(2);
    }
    if (args.customization_path) |path| {
        if (pathsOverlapCanonically(arena, init.io, lock_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result lock from customization config: {t}\n", .{err});
            std.process.exit(1);
        }) {
            std.debug.print("zvmi-image-builder: result lock and customization config must be distinct\n", .{});
            std.process.exit(2);
        }
    }
    for (args.customization_source_paths) |path| {
        if (pathsOverlapCanonically(arena, init.io, lock_path, path) catch |err| {
            std.debug.print("zvmi-image-builder: cannot isolate result lock from customization source: {t}\n", .{err});
            std.process.exit(1);
        }) {
            std.debug.print("zvmi-image-builder: result lock and customization sources must be distinct\n", .{});
            std.process.exit(2);
        }
    }
    const lock_file = try acquireBundleLock(init.io, lock_path);
    defer lock_file.close(init.io);

    if (args.reuse_success and try hasReusableSuccess(
        init.io,
        arena,
        argv,
        args.iso_path,
        args.container,
        args.bundle_output_path,
        args.image_basename,
        args.customization_path,
        args.customization_source_paths,
    )) return;
    const reuse_key_before = try computeReuseKey(
        arena,
        init.io,
        argv,
        args.iso_path,
        args.container,
        args.customization_path,
        args.customization_source_paths,
    );
    try resetBundle(init.io, args.bundle_output_path);
    std.Io.Dir.cwd().createDirPath(init.io, args.bundle_output_path) catch |err| {
        std.debug.print("zvmi-image-builder: cannot create result bundle: {t}\n", .{err});
        std.process.exit(1);
    };
    const output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, args.image_basename });
    const plan_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "plan.json" });
    const diagnostics_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "diagnostics.json" });
    const provenance_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "provenance.json" });
    const reuse_key_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "reuse-key" });
    const status_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "status" });
    try writeBytes(init.io, plan_output_path, "null\n");
    try writeBytes(init.io, diagnostics_output_path, "[]\n");
    try writeBytes(init.io, provenance_output_path, "null\n");

    const customization = customization_loader.load(
        arena,
        init.io,
        args.customization_path,
        args.customization_source_paths,
    ) catch |err| {
        std.debug.print("zvmi-image-builder: invalid customization: {t}\n", .{err});
        std.process.exit(2);
    };

    const request = zvmi.customize.Request{
        .api_version = args.api_version,
        .target_architecture = args.architecture,
        .input = .{ .iso_oci = .{
            .iso_path = args.iso_path,
            .container = switch (args.container) {
                .host_path => |path| .{ .host_path = path },
                .registry => |declared| .{ .registry = .{
                    .reference = declared.reference,
                    .access = declared.access() catch unreachable,
                    .signature = declared.signature(),
                } },
            },
            .rootfs_path_in_iso = args.rootfs_path,
        } },
        .output = .{
            .path = output_path,
            .format = args.format,
            .size = args.size,
        },
        .storage = .{ .fresh = .{
            .generation = args.generation,
            .esp_size = args.esp_size,
            .ext4_label = args.ext4_label,
            .skip_iso_rootfs = args.skip_iso_rootfs,
            .root_filesystem = args.root_filesystem,
        } },
        .boot_security = .{
            .boot_mode = args.boot_mode,
            .verity = args.verity,
            .extra_kernel_options = args.extra_kernel_options,
            .uki = args.uki,
            .signing = args.uki_signing,
        },
        .os = customization.os,
        .generalization = customization.generalization,
        .execution = .{ .workspace_path = args.bundle_output_path },
        .reproducibility = .{
            .seed = args.seed,
            .source_date_epoch = args.source_date_epoch,
        },
        .limits = args.limits,
    };

    const host_architecture: zvmi.customize.Architecture = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => {
            std.debug.print("zvmi-image-builder: unsupported host architecture: {t}\n", .{builtin.cpu.arch});
            std.process.exit(2);
        },
    };
    var resolved = zvmi.customize.resolve(init.gpa, &request, .{
        .host_architecture = host_architecture,
    }) catch |err| {
        std.debug.print("zvmi-image-builder: request resolution failed: {t}\n", .{err});
        std.process.exit(1);
    };
    defer resolved.deinit(init.gpa);

    if (resolved.plan) |*plan| {
        writePlan(init.gpa, init.io, plan_output_path, plan) catch |err| {
            std.debug.print("zvmi-image-builder: cannot write plan: {t}\n", .{err});
            std.process.exit(1);
        };
    }
    if (resolved.diagnostics.hasErrors()) {
        writeDiagnostics(init.gpa, init.io, diagnostics_output_path, resolved.diagnostics, false) catch |err| {
            std.debug.print("zvmi-image-builder: cannot write diagnostics: {t}\n", .{err});
            std.process.exit(1);
        };
        try writeBytes(init.io, status_output_path, "failure\n");
        return;
    }

    // The build process's own environment, forwarded only to a declared UKI
    // signing provider. `zvmi sign` reaches Azure Trusted Signing with a
    // GitHub OIDC request URL and token it finds there, so a signer handed a
    // curated environment is a signer that cannot sign.
    var platform = zvmi.customize.Platform.system();
    platform.signing_environ = init.minimal.environ;
    // The same environment, granted separately, because a request that names
    // `--registry-password-env` has said out loud which variable it wants
    // read and a plan that names none reads nothing from here.
    platform.registry_environ = init.minimal.environ;

    if (args.preflight_only) {
        var report = try zvmi.customize.preflight(init.gpa, init.io, &resolved.plan.?, platform);
        defer report.deinit(init.gpa);
        try writeDiagnostics(init.gpa, init.io, diagnostics_output_path, report.diagnostics, false);
        try writeBytes(init.io, status_output_path, if (report.ready()) "success\n" else "failure\n");
        return;
    }

    var console = ConsoleEvents{ .verbose = args.verbose };
    var outcome = zvmi.customize.execute(
        init.gpa,
        init.io,
        &resolved.plan.?,
        platform,
        .{ .context = &console, .emitFn = ConsoleEvents.emit },
    ) catch |err| {
        std.debug.print("zvmi-image-builder: execution setup failed: {t}\n", .{err});
        std.process.exit(1);
    };
    defer outcome.deinit(init.gpa);

    writeDiagnostics(init.gpa, init.io, diagnostics_output_path, outcome.diagnostics, false) catch |err| {
        std.debug.print("zvmi-image-builder: cannot write diagnostics: {t}\n", .{err});
        std.process.exit(1);
    };
    const result = if (outcome.result) |*success| success else {
        try writeBytes(init.io, status_output_path, "failure\n");
        return;
    };
    const reuse_key_after = try computeReuseKey(
        arena,
        init.io,
        argv,
        args.iso_path,
        args.container,
        args.customization_path,
        args.customization_source_paths,
    );
    if (!std.mem.eql(u8, &reuse_key_before, &reuse_key_after)) {
        try writeBytes(init.io, status_output_path, "failure\n");
        return error.SourceChangedDuringBuild;
    }
    writeProvenance(init.gpa, init.io, provenance_output_path, result.provenance) catch |err| {
        std.debug.print("zvmi-image-builder: cannot write provenance: {t}\n", .{err});
        std.process.exit(1);
    };
    try writeReuseKey(init.io, reuse_key_output_path, reuse_key_before);
    try writeBytes(init.io, status_output_path, "success\n");
}

/// Returns the digest-form reference for a declared image, resolving a tag
/// against the registry if that is what was named.
///
/// A request may only hold a digest, and a person holds a tag. Resolving it
/// here rather than refusing means the two-step workflow is one step for
/// anyone who does not need it to be two, and reporting what it resolved to
/// on stderr means the digest is still stated out loud rather than followed
/// silently -- which is the whole reason the request wants one.
fn pinIfTagged(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    declared: RegistryArg,
) ![]const u8 {
    const parsed = try zvmi.oci.reference.parse(declared.reference, .source);
    const selection = switch (parsed) {
        .registry => |value| value.selection,
        .layout => return error.NotARegistryReference,
    };
    if (selection) |value| {
        if (value == .digest) return declared.reference;
    }
    var pin = try zvmi.customize.pinDeclaredImage(
        allocator,
        io,
        environ,
        declared.reference,
        try declared.access(),
    );
    defer pin.deinit();
    std.debug.print(
        "zvmi-image-builder: pinned {s} to {s}\n",
        .{ declared.reference, pin.reference },
    );
    return allocator.dupe(u8, pin.reference);
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !ParsedArgs {
    var api_version: u32 = zvmi.customize.current_api_version;
    var architecture: ?zvmi.customize.Architecture = null;
    var iso_path: ?[]const u8 = null;
    var container: ?ContainerArg = null;
    var registry = RegistryArg{ .reference = "" };
    var rootfs_path: ?[]const u8 = null;
    var bundle_output_path: ?[]const u8 = null;
    var image_basename: ?[]const u8 = null;
    var format: ?zvmi.customize.OutputFormat = null;
    var size: ?u64 = null;
    var generation: zvmi.azure.Generation = .gen2;
    var skip_iso_rootfs = false;
    var esp_size: u64 = zvmi.build_image.default_esp_size;
    var ext4_label: []const u8 = "rootfs";
    var root_filesystem: zvmi.layout.FilesystemKind = .ext4;
    var verity = false;
    var extra_kernel_options: []const u8 = "";
    var boot_mode: zvmi.bootconfig.BootMode = .bls_only;
    var uki: zvmi.customize.UkiOptions = .{};
    var uki_signing_certificate_path: ?[]const u8 = null;
    var uki_signing_command: ?[]const u8 = null;
    var uki_signing_argument: []const u8 = "";
    var customization_path: ?[]const u8 = null;
    var customization_sources = std.array_list.Managed([]const u8).init(allocator);
    errdefer customization_sources.deinit();
    var seed: ?zvmi.customize.Seed = null;
    var source_date_epoch: ?u64 = null;
    var limits: zvmi.limits.ImportLimits = .{};
    var preflight_only = false;
    var reuse_success = false;
    var verbose = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--skip-iso-rootfs")) {
            skip_iso_rootfs = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--verity")) {
            verity = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--preflight-only")) {
            preflight_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--reuse-success")) {
            reuse_success = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--registry-plain-http")) {
            registry.plain_http = true;
            continue;
        }

        i += 1;
        if (i >= args.len) return error.MissingArgumentValue;
        const value = args[i];
        if (std.mem.eql(u8, arg, "--api-version")) {
            api_version = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            architecture = parseArchitecture(value) orelse return error.InvalidArchitecture;
        } else if (std.mem.eql(u8, arg, "--iso")) {
            iso_path = value;
        } else if (std.mem.eql(u8, arg, "--container")) {
            // A `docker://` reference and a path are told apart by the scheme
            // and by nothing else, so no existing path can be reinterpreted
            // as a registry by accident.
            if (std.mem.startsWith(u8, value, "docker://")) {
                registry.reference = value;
                container = .{ .registry = registry };
            } else {
                container = .{ .host_path = value };
            }
        } else if (std.mem.eql(u8, arg, "--registry-username")) {
            registry.username = value;
        } else if (std.mem.eql(u8, arg, "--registry-password-file")) {
            if (registry.password != null) return error.ConflictingRegistryPassword;
            registry.password = .{ .host_path = value };
        } else if (std.mem.eql(u8, arg, "--registry-password-env")) {
            if (registry.password != null) return error.ConflictingRegistryPassword;
            registry.password = .{ .host_environment = value };
        } else if (std.mem.eql(u8, arg, "--registry-tls-ca")) {
            registry.tls_ca = value;
        } else if (std.mem.eql(u8, arg, "--registry-signature-key")) {
            registry.signature_key = value;
        } else if (std.mem.eql(u8, arg, "--rootfs-path")) {
            rootfs_path = value;
        } else if (std.mem.eql(u8, arg, "--bundle-output")) {
            bundle_output_path = value;
        } else if (std.mem.eql(u8, arg, "--image-basename")) {
            image_basename = value;
        } else if (std.mem.eql(u8, arg, "-O")) {
            format = parseFormat(value) orelse return error.InvalidFormat;
        } else if (std.mem.eql(u8, arg, "--size")) {
            size = try zvmi.parseSize(value);
        } else if (std.mem.eql(u8, arg, "--generation")) {
            generation = parseGeneration(value) orelse return error.InvalidGeneration;
        } else if (std.mem.eql(u8, arg, "--esp-size")) {
            esp_size = try zvmi.parseSize(value);
        } else if (std.mem.eql(u8, arg, "--ext4-label")) {
            ext4_label = value;
        } else if (std.mem.eql(u8, arg, "--root-filesystem")) {
            if (std.mem.eql(u8, value, "ext4")) {
                root_filesystem = .ext4;
            } else if (std.mem.eql(u8, value, "xfs")) {
                root_filesystem = .xfs;
            } else {
                return error.InvalidRootFilesystem;
            }
        } else if (std.mem.eql(u8, arg, "--extra-kernel-options")) {
            extra_kernel_options = value;
        } else if (std.mem.eql(u8, arg, "--boot-mode")) {
            boot_mode = parseBootMode(value) orelse return error.InvalidBootMode;
        } else if (std.mem.eql(u8, arg, "--stub-source-path")) {
            uki.stub_source_path = value;
        } else if (std.mem.eql(u8, arg, "--os-release-source-path")) {
            uki.os_release_source_path = value;
        } else if (std.mem.eql(u8, arg, "--splash-source-path")) {
            uki.splash_source_path = value;
        } else if (std.mem.eql(u8, arg, "--uki-output-directory")) {
            uki.output_directory = value;
        } else if (std.mem.eql(u8, arg, "--uki-signing-certificate")) {
            uki_signing_certificate_path = value;
        } else if (std.mem.eql(u8, arg, "--uki-signing-command")) {
            uki_signing_command = value;
        } else if (std.mem.eql(u8, arg, "--uki-signing-argument")) {
            uki_signing_argument = value;
        } else if (std.mem.eql(u8, arg, "--customization")) {
            customization_path = value;
        } else if (std.mem.eql(u8, arg, "--customization-source")) {
            try customization_sources.append(value);
        } else if (std.mem.eql(u8, arg, "--seed")) {
            if (value.len != 64) return error.InvalidSeed;
            var bytes: [32]u8 = undefined;
            const decoded = try std.fmt.hexToBytes(&bytes, value);
            if (decoded.len != bytes.len) return error.InvalidSeed;
            seed = .{ .bytes = bytes };
        } else if (std.mem.eql(u8, arg, "--source-date-epoch")) {
            source_date_epoch = try std.fmt.parseInt(u64, value, 10);
        } else if (try limits.parseFlag(arg, value)) {
            // Handled: `arg` named an import limit and `value` raised it.
        } else {
            return error.UnexpectedArgument;
        }
    }

    // Both halves or neither: a certificate with no provider names a signer
    // that never runs, and a provider with no certificate has nothing to
    // check its result against.
    if ((uki_signing_certificate_path == null) != (uki_signing_command == null)) {
        return error.IncompleteUkiSigning;
    }

    // Order-independent: the registry options are collected as they are seen
    // and applied here, so `--registry-username x --container docker://...`
    // and the reverse order mean the same thing.
    const resolved_container = container orelse return error.MissingContainer;
    switch (resolved_container) {
        .registry => {
            _ = try registry.access();
            container = .{ .registry = registry };
        },
        // Refused rather than ignored: a registry flag beside a local layout
        // is a request nobody can satisfy, and silently dropping it would
        // make a build that reads no credential look like one that did.
        .host_path => {
            if (registry.username != null or registry.password != null or
                registry.tls_ca != null or registry.plain_http or
                registry.signature_key != null)
            {
                return error.RegistryOptionsWithoutRegistry;
            }
        },
    }

    return .{
        .api_version = api_version,
        .architecture = architecture orelse return error.MissingArchitecture,
        .iso_path = iso_path orelse return error.MissingIso,
        .container = container.?,
        .rootfs_path = rootfs_path orelse return error.MissingRootfsPath,
        .bundle_output_path = bundle_output_path orelse return error.MissingBundleOutput,
        .image_basename = image_basename orelse return error.MissingImageBasename,
        .format = format orelse return error.MissingFormat,
        .size = size orelse return error.MissingSize,
        .generation = generation,
        .skip_iso_rootfs = skip_iso_rootfs,
        .esp_size = esp_size,
        .ext4_label = ext4_label,
        .root_filesystem = root_filesystem,
        .verity = verity,
        .extra_kernel_options = extra_kernel_options,
        .boot_mode = boot_mode,
        .uki = uki,
        .uki_signing = if (uki_signing_certificate_path) |certificate_path| .{
            .certificate = .{ .host_path = certificate_path },
            .provider = .{ .external_command = .{
                .executable_path = uki_signing_command.?,
                .argument = uki_signing_argument,
            } },
        } else null,
        .customization_path = customization_path,
        .customization_source_paths = try customization_sources.toOwnedSlice(),
        .seed = seed orelse return error.MissingSeed,
        .source_date_epoch = source_date_epoch orelse return error.MissingSourceDateEpoch,
        .limits = limits,
        .preflight_only = preflight_only,
        .reuse_success = reuse_success,
        .verbose = verbose,
    };
}

fn parseArchitecture(value: []const u8) ?zvmi.customize.Architecture {
    if (std.mem.eql(u8, value, "x86_64")) return .x86_64;
    if (std.mem.eql(u8, value, "aarch64")) return .aarch64;
    return null;
}

fn parseFormat(value: []const u8) ?zvmi.customize.OutputFormat {
    return zvmi.customize.OutputFormat.parseName(value);
}

fn parseGeneration(value: []const u8) ?zvmi.azure.Generation {
    if (std.mem.eql(u8, value, "1")) return .gen1;
    if (std.mem.eql(u8, value, "2")) return .gen2;
    return null;
}

fn parseBootMode(value: []const u8) ?zvmi.bootconfig.BootMode {
    if (std.mem.eql(u8, value, "bls")) return .bls_only;
    if (std.mem.eql(u8, value, "uki")) return .uki_only;
    if (std.mem.eql(u8, value, "both")) return .bls_and_uki;
    return null;
}

fn isBasename(path: []const u8) bool {
    return path.len != 0 and
        !std.fs.path.isAbsolute(path) and
        std.mem.eql(u8, path, std.fs.path.basename(path)) and
        !std.mem.eql(u8, path, ".") and
        !std.mem.eql(u8, path, "..");
}

fn isReservedBasename(path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(path, "status") or
        std.ascii.eqlIgnoreCase(path, "plan.json") or
        std.ascii.eqlIgnoreCase(path, "diagnostics.json") or
        std.ascii.eqlIgnoreCase(path, "provenance.json") or
        std.ascii.eqlIgnoreCase(path, "reuse-key");
}

fn pathsOverlapCanonically(
    allocator: std.mem.Allocator,
    io: std.Io,
    first: []const u8,
    second: []const u8,
) !bool {
    const canonical_first = try canonicalProspectivePath(allocator, io, first);
    const canonical_second = try canonicalProspectivePath(allocator, io, second);
    return pathOverlaps(canonical_first, canonical_second);
}

fn canonicalProspectivePath(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    const resolved = try std.fs.path.resolve(allocator, &.{path});
    const absolute = if (std.fs.path.isAbsolute(resolved))
        resolved
    else blk: {
        var cwd_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const cwd_len = try std.Io.Dir.cwd().realPathFile(io, ".", &cwd_buffer);
        break :blk try std.fs.path.join(allocator, &.{ cwd_buffer[0..cwd_len], resolved });
    };
    var candidate: []const u8 = absolute;
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    while (true) {
        if (std.Io.Dir.cwd().realPathFile(io, candidate, &buffer)) |len| {
            return try std.mem.concat(allocator, u8, &.{ buffer[0..len], absolute[candidate.len..] });
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const parent = std.fs.path.dirname(candidate) orelse return absolute;
        if (std.mem.eql(u8, parent, candidate)) return absolute;
        candidate = parent;
    }
}

fn pathOverlaps(first: []const u8, second: []const u8) bool {
    if (std.mem.eql(u8, first, second)) return true;
    return pathContains(first, second) or pathContains(second, first);
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    if (!std.mem.startsWith(u8, child, parent) or child.len <= parent.len) return false;
    return std.fs.path.isSep(parent[parent.len - 1]) or std.fs.path.isSep(child[parent.len]);
}

fn hasReusableSuccess(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    iso_path: []const u8,
    container: ContainerArg,
    bundle_path: []const u8,
    image_basename: []const u8,
    customization_path: ?[]const u8,
    customization_source_paths: []const []const u8,
) !bool {
    const status_path = try std.fs.path.join(allocator, &.{ bundle_path, "status" });
    const status = std.Io.Dir.cwd().readFileAlloc(io, status_path, allocator, .limited(64)) catch return false;
    if (!std.mem.eql(u8, std.mem.trim(u8, status, " \r\n\t"), "success")) return false;

    const required_files = [_][]const u8{ image_basename, "plan.json", "diagnostics.json", "provenance.json", "reuse-key" };
    for (required_files) |basename| {
        const path = try std.fs.path.join(allocator, &.{ bundle_path, basename });
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
        if (stat.kind != .file) return false;
    }
    const reuse_key_path = try std.fs.path.join(allocator, &.{ bundle_path, "reuse-key" });
    const stored_key = std.Io.Dir.cwd().readFileAlloc(io, reuse_key_path, allocator, .limited(128)) catch return false;
    const current_key = computeReuseKey(
        allocator,
        io,
        argv,
        iso_path,
        container,
        customization_path,
        customization_source_paths,
    ) catch return false;
    const current_hex = std.fmt.bytesToHex(current_key, .lower);
    return std.mem.eql(u8, std.mem.trim(u8, stored_key, " \r\n\t"), &current_hex);
}

fn resetBundle(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind == .directory) {
        try cwd.deleteTree(io, path);
    } else {
        try cwd.deleteFile(io, path);
    }
}

fn acquireBundleLock(io: std.Io, path: []const u8) !std.Io.File {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |parent| try cwd.createDirPath(io, parent);
    return cwd.createFile(io, path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
    });
}

fn writeReuseKey(
    io: std.Io,
    path: []const u8,
    key: [32]u8,
) !void {
    const key_hex = std.fmt.bytesToHex(key, .lower);
    var bytes: [key_hex.len + 1]u8 = undefined;
    @memcpy(bytes[0..key_hex.len], &key_hex);
    bytes[key_hex.len] = '\n';
    try writeBytes(io, path, &bytes);
}

fn computeReuseKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    iso_path: []const u8,
    container: ContainerArg,
    customization_path: ?[]const u8,
    customization_source_paths: []const []const u8,
) ![32]u8 {
    const executable_digest = try zvmi.customize.hashSourcePath(allocator, io, argv[0]);
    const iso_digest = try zvmi.customize.hashSourcePath(allocator, io, iso_path);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zvmi-image-builder-reuse-v2\x00");
    for (argv[1..]) |arg| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, arg.len, .big);
        hash.update(&length);
        hash.update(arg);
    }
    hash.update(&executable_digest.bytes);
    hash.update(&iso_digest.bytes);
    switch (container) {
        .host_path => |path| {
            const digest = try zvmi.customize.hashSourcePath(allocator, io, path);
            hash.update(&digest.bytes);
        },
        // The pinned reference *is* the content digest, so hashing it says
        // exactly what hashing a local layout's bytes would say, and says it
        // without a network request. It is hashed rather than the raw
        // argument because a tag on the command line was pinned above, and
        // reusing a build across a tag that moved would be wrong.
        .registry => |declared| hash.update(declared.reference),
    }
    if (customization_path) |path| {
        const digest = try zvmi.customize.hashSourcePath(allocator, io, path);
        hash.update(&digest.bytes);
    }
    for (customization_source_paths) |path| {
        const digest = try zvmi.customize.hashSourcePath(allocator, io, path);
        hash.update(&digest.bytes);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn writePlan(allocator: std.mem.Allocator, io: std.Io, path: []const u8, plan: *const zvmi.customize.ResolvedPlan) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try zvmi.customize.writePlanJson(plan, &output.writer);
    try writeBytes(io, path, output.written());
}

fn writeDiagnostics(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diagnostics: zvmi.customize.DiagnosticSet,
    print: bool,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try zvmi.customize.writeDiagnosticsJson(diagnostics, &output.writer);
    try writeBytes(io, path, output.written());
    if (print) std.debug.print("{s}\n", .{output.written()});
}

fn writeProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    provenance: zvmi.customize.Provenance,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try zvmi.customize.writeProvenanceJson(provenance, &output.writer);
    try writeBytes(io, path, output.written());
}

fn writeBytes(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

const ConsoleEvents = struct {
    verbose: bool,

    fn emit(context: ?*anyopaque, event: zvmi.customize.ExecutionEvent) void {
        const self: *ConsoleEvents = @ptrCast(@alignCast(context.?));
        switch (event) {
            .progress => |progress| if (self.verbose) std.debug.print("zvmi-image-builder: {s}\n", .{progress.message}),
            .diagnostic => {},
        }
    }
};

// The arguments the exported build helper generates, as a baseline every test
// below changes one thing in.
fn testArgs(extra: []const []const u8, buffer: [][]const u8) []const []const u8 {
    const base = [_][]const u8{
        "--architecture",      "x86_64",
        "--iso",               "input.iso",
        "--rootfs-path",       "rootfs.img",
        "--bundle-output",     "result",
        "--image-basename",    "image.vhd",
        "-O",                  "vhd",
        "--size",              "4G",
        "--seed",              "00" ** 32,
        "--source-date-epoch", "0",
    };
    @memcpy(buffer[0..base.len], &base);
    @memcpy(buffer[base.len..][0..extra.len], extra);
    return buffer[0 .. base.len + extra.len];
}

test "a docker reference is a registry container and a path is not" {
    var buffer: [40][]const u8 = undefined;
    const registry_parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "docker://registry.example/team/image:stable" },
        &buffer,
    ));
    try std.testing.expect(registry_parsed.container == .registry);
    try std.testing.expectEqualStrings(
        "docker://registry.example/team/image:stable",
        registry_parsed.container.registry.reference,
    );

    var path_buffer: [40][]const u8 = undefined;
    const path_parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "./oci-layout" },
        &path_buffer,
    ));
    try std.testing.expect(path_parsed.container == .host_path);
    try std.testing.expectEqualStrings("./oci-layout", path_parsed.container.host_path);
}

test "a registry option beside a local layout is refused rather than ignored" {
    var buffer: [40][]const u8 = undefined;
    try std.testing.expectError(error.RegistryOptionsWithoutRegistry, parseArgs(
        std.testing.allocator,
        testArgs(&.{
            "--container",         "./oci-layout",
            "--registry-username", "builder",
        }, &buffer),
    ));
}

test "the output root filesystem defaults to ext4 and parses an explicit choice" {
    var default_buffer: [40][]const u8 = undefined;
    const default_parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "./oci-layout" },
        &default_buffer,
    ));
    try std.testing.expectEqual(zvmi.layout.FilesystemKind.ext4, default_parsed.root_filesystem);

    var xfs_buffer: [40][]const u8 = undefined;
    const xfs_parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "./oci-layout", "--root-filesystem", "xfs" },
        &xfs_buffer,
    ));
    try std.testing.expectEqual(zvmi.layout.FilesystemKind.xfs, xfs_parsed.root_filesystem);

    var ext4_buffer: [40][]const u8 = undefined;
    const ext4_parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "./oci-layout", "--root-filesystem", "ext4" },
        &ext4_buffer,
    ));
    try std.testing.expectEqual(zvmi.layout.FilesystemKind.ext4, ext4_parsed.root_filesystem);

    var bad_buffer: [40][]const u8 = undefined;
    try std.testing.expectError(error.InvalidRootFilesystem, parseArgs(
        std.testing.allocator,
        testArgs(&.{ "--container", "./oci-layout", "--root-filesystem", "btrfs" }, &bad_buffer),
    ));
}

test "a registry credential needs both halves" {
    var name_only: [40][]const u8 = undefined;
    try std.testing.expectError(error.IncompleteRegistryCredential, parseArgs(
        std.testing.allocator,
        testArgs(&.{
            "--container",         "docker://registry.example/team/image:stable",
            "--registry-username", "builder",
        }, &name_only),
    ));

    var password_only: [40][]const u8 = undefined;
    try std.testing.expectError(error.IncompleteRegistryCredential, parseArgs(
        std.testing.allocator,
        testArgs(&.{
            "--container",              "docker://registry.example/team/image:stable",
            "--registry-password-file", "secret",
        }, &password_only),
    ));
}

test "a registry password comes from a file or the environment, not both" {
    var buffer: [40][]const u8 = undefined;
    try std.testing.expectError(error.ConflictingRegistryPassword, parseArgs(
        std.testing.allocator,
        testArgs(&.{
            "--container",              "docker://registry.example/team/image:stable",
            "--registry-username",      "builder",
            "--registry-password-file", "secret",
            "--registry-password-env",  "REGISTRY_PASSWORD",
        }, &buffer),
    ));
}

test "registry options apply whichever side of --container they are given" {
    var before: [40][]const u8 = undefined;
    const parsed_before = try parseArgs(std.testing.allocator, testArgs(&.{
        "--registry-username",                       "builder",
        "--registry-password-env",                   "REGISTRY_PASSWORD",
        "--registry-plain-http",                     "--container",
        "docker://127.0.0.1:5000/team/image:stable",
    }, &before));
    const access_before = try parsed_before.container.registry.access();
    try std.testing.expect(access_before.plain_http);
    try std.testing.expectEqualStrings("builder", access_before.credential.?.username);
    try std.testing.expectEqualStrings(
        "REGISTRY_PASSWORD",
        access_before.credential.?.password.host_environment,
    );

    var after: [40][]const u8 = undefined;
    const parsed_after = try parseArgs(std.testing.allocator, testArgs(&.{
        "--container",             "docker://127.0.0.1:5000/team/image:stable",
        "--registry-username",     "builder",
        "--registry-password-env", "REGISTRY_PASSWORD",
        "--registry-plain-http",
    }, &after));
    const access_after = try parsed_after.container.registry.access();
    try std.testing.expectEqual(access_before.plain_http, access_after.plain_http);
    try std.testing.expectEqualStrings(
        access_before.credential.?.username,
        access_after.credential.?.username,
    );
}

// The password is a name of somewhere the password lives. A test that only
// checked both halves were present would pass on a version that carried the
// material, which is the mistake worth fencing.
test "a registry password is a locator and never material" {
    var buffer: [40][]const u8 = undefined;
    const parsed = try parseArgs(std.testing.allocator, testArgs(&.{
        "--container",              "docker://registry.example/team/image:stable",
        "--registry-username",      "builder",
        "--registry-password-file", "/run/secrets/registry",
    }, &buffer));
    const access = try parsed.container.registry.access();
    try std.testing.expectEqualStrings(
        "/run/secrets/registry",
        access.credential.?.password.host_path,
    );
}

test "a signature key is carried as a path and not read here" {
    var buffer: [40][]const u8 = undefined;
    const parsed = try parseArgs(std.testing.allocator, testArgs(&.{
        "--container",              "docker://registry.example/team/image:stable",
        "--registry-signature-key", "/etc/zvmi/cosign.pub",
    }, &buffer));
    try std.testing.expectEqualStrings(
        "/etc/zvmi/cosign.pub",
        parsed.container.registry.signature().?.key.host_path,
    );
}

test "an image with no declared key asks for no signature at all" {
    var buffer: [40][]const u8 = undefined;
    const parsed = try parseArgs(std.testing.allocator, testArgs(
        &.{ "--container", "docker://registry.example/team/image:stable" },
        &buffer,
    ));
    try std.testing.expect(parsed.container.registry.signature() == null);
}

test "a signature key beside a local layout is refused rather than ignored" {
    var buffer: [40][]const u8 = undefined;
    try std.testing.expectError(error.RegistryOptionsWithoutRegistry, parseArgs(
        std.testing.allocator,
        testArgs(&.{
            "--container",              "./oci-layout",
            "--registry-signature-key", "/etc/zvmi/cosign.pub",
        }, &buffer),
    ));
}
