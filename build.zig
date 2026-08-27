const std = @import("std");

const image_build = @import("build/image.zig");
const iso_build = @import("build/iso.zig");
const oci_build = @import("build/oci.zig");

const AzureLinuxArchitecture = enum {
    x86_64,
    aarch64,
};

const AzureLinuxFlavor = enum {
    core,
    full,
};

const Ubuntu2604Architecture = enum {
    x86_64,
    aarch64,
};

const Ubuntu2604Flavor = enum {
    core,
    full,
    baremetal,

    /// Whether the flavor needs the static guest binaries built alongside the
    /// image. Bare metal is core aimed at a physical machine, so it runs the
    /// same PID 1.
    fn needsGuestArtifacts(self: Ubuntu2604Flavor) bool {
        return self != .full;
    }
};

pub const ImageFormat = image_build.Format;
pub const ImageGeneration = image_build.Generation;
pub const ImageBootMode = image_build.BootMode;
pub const ImageArchitecture = image_build.Architecture;
pub const ImageReproducibility = image_build.Reproducibility;
pub const ImageUkiOptions = image_build.UkiOptions;
pub const ImageContainer = image_build.Container;
pub const ImageInput = image_build.Input;
pub const ImageOutput = image_build.Output;
pub const ImageOptions = image_build.Options;
pub const ImageResult = image_build.Result;
pub const addImage = image_build.add;
pub const PreservedImageInput = image_build.PreservedInput;
pub const PreservedImageRootPartition = image_build.PreservedRootPartition;
pub const PreservedImageFileSource = image_build.PreservedFileSource;
pub const PreservedImageOperation = image_build.PreservedOperation;
pub const PreservedImageBackend = image_build.PreservedBackend;
pub const PreservedImageOptions = image_build.PreservedOptions;
pub const addPreservedImage = image_build.addPreserved;
pub const OciPullPlatform = oci_build.Platform;
pub const OciPullOptions = oci_build.Options;
pub const OciPullResult = oci_build.Result;
pub const addOciPull = oci_build.add;

pub const IsoArchitecture = iso_build.Architecture;
pub const IsoCompression = iso_build.Compression;
pub const IsoBootPlatform = iso_build.BootPlatform;
pub const IsoBootImage = iso_build.BootImage;
pub const IsoContainer = iso_build.Container;
pub const IsoOsCustomization = iso_build.OsCustomization;
pub const IsoOptions = iso_build.Options;
pub const IsoResult = iso_build.Result;
pub const addIso = iso_build.add;
pub const RecustomizeIsoOptions = iso_build.RecustomizeOptions;
pub const RecustomizeIsoResult = iso_build.RecustomizeResult;
pub const addRecustomizeIso = iso_build.addRecustomize;

test {
    std.testing.refAllDecls(oci_build);
    std.testing.refAllDecls(iso_build);
}

fn zstdDependency(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Dependency {
    return b.dependency("zstd", .{
        .target = target,
        .optimize = optimize,
        .tools = false,
        .shared = false,
        .multithread = false,
    });
}

fn addZstdHeaders(module: *std.Build.Module, dependency: *std.Build.Dependency) void {
    module.addIncludePath(dependency.path("lib"));
}

fn addZstdLibrary(module: *std.Build.Module, dependency: *std.Build.Dependency) void {
    addZstdHeaders(module, dependency);
    module.linkLibrary(dependency.artifact("zstd"));
}

const Ubuntu2604CoreArtifacts = struct {
    mizinit: *std.Build.Step.Compile,
    azagent: *std.Build.Step.Compile,
};

fn addUbuntu2604CoreArtifacts(
    b: *std.Build,
    architecture: Ubuntu2604Architecture,
) Ubuntu2604CoreArtifacts {
    const guest_target = b.resolveTargetQuery(.{
        .cpu_arch = switch (architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .os_tag = .linux,
    });
    const guest_zstd = zstdDependency(b, guest_target, .ReleaseSmall);
    const cdrom_mod = b.createModule(.{
        .root_source_file = b.path("azagent/cdrom.zig"),
        .target = guest_target,
        .optimize = .ReleaseSmall,
    });
    const mizinit = b.addExecutable(.{
        .name = b.fmt("ubuntu2604-mizinit-{s}", .{@tagName(architecture)}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("mizinit/init.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
            .imports = &.{
                .{ .name = "provisioning_media", .module = cdrom_mod },
            },
        }),
        .linkage = .static,
    });
    const miz_guest_mod = b.createModule(.{
        .root_source_file = b.path("packages/miz/src/root.zig"),
        .target = guest_target,
        .optimize = .ReleaseSmall,
    });
    addZstdHeaders(miz_guest_mod, guest_zstd);
    const wireserver_guest_mod = b.createModule(.{
        .root_source_file = b.path("wireserver/wireserver.zig"),
        .target = guest_target,
        .optimize = .ReleaseSmall,
    });
    const azagent = b.addExecutable(.{
        .name = b.fmt("ubuntu2604-azagent-{s}", .{@tagName(architecture)}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("azagent/main.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
            .imports = &.{
                .{ .name = "wireserver", .module = wireserver_guest_mod },
                .{ .name = "miz", .module = miz_guest_mod },
            },
        }),
        .linkage = .static,
    });
    return .{ .mizinit = mizinit, .azagent = azagent };
}

/// A tiny statically linked binary that native Ubuntu 26.04 core acceptance
/// pushes into the running guest over SSH to confirm Binder workload device
/// usability (open + `BINDER_VERSION`) rather than only checking paths. It
/// is acceptance tooling, not an image artifact: `build_generalized_ubuntu2604`
/// never receives it, unlike `mizinit`/`azagent` above.
fn addUbuntu2604BinderProbe(
    b: *std.Build,
    architecture: Ubuntu2604Architecture,
) *std.Build.Step.Compile {
    const guest_target = b.resolveTargetQuery(.{
        .cpu_arch = switch (architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .os_tag = .linux,
    });
    return b.addExecutable(.{
        .name = b.fmt("ubuntu2604-binder-probe-{s}", .{@tagName(architecture)}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/ubuntu2604_binder_probe.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
        }),
        .linkage = .static,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // `std.Build.standardOptimizeOption` with no explicit flag, except the
    // fallback is ReleaseSafe rather than Debug. What this repository builds
    // is image tooling -- decompression, hashing, dependency solving, ext4
    // and QCOW2 writes -- and Debug makes that an order of magnitude slower:
    // a bare-metal aarch64 Ubuntu image takes about 36 minutes at Debug
    // against about 6 optimized, on one machine with one warm package cache.
    // Every release workflow already passes `-Doptimize=ReleaseSafe`, so the
    // Debug default only ever applied to invocations that had no reason to
    // want it, including `zig build generalized-ubuntu2604`. Safety checks
    // stay on: this parses archives it did not write and produces filesystem
    // images a machine boots from.
    //
    // Spelled out rather than passing `preferred_optimize_mode`, which would
    // withdraw `-Doptimize` in favour of a `-Drelease` bool and break every
    // caller that names a mode.
    const default_optimize: std.builtin.OptimizeMode = switch (b.release_mode) {
        .off, .any, .safe => .ReleaseSafe,
        .fast => .ReleaseFast,
        .small => .ReleaseSmall,
    };
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size",
    ) orelse default_optimize;
    // CI invokes this with test-ci, whose generalized-image checks and
    // mizguest step already compile the remaining production artifacts.
    const ci_production_entrypoint_check = b.step(
        "check-ci-production-entrypoints",
        "Compile production entry points not already reached by test-ci",
    );
    const azurelinux_architecture = b.option(
        AzureLinuxArchitecture,
        "azurelinux-arch",
        "Azure Linux guest architecture: x86_64 (default) or aarch64",
    ) orelse .x86_64;
    const azurelinux_flavor = b.option(
        AzureLinuxFlavor,
        "azurelinux-flavor",
        "Azure Linux guest flavor: core (default, mizinit) or full (official vm-base/systemd)",
    ) orelse .core;
    const ubuntu2604_architecture = b.option(
        Ubuntu2604Architecture,
        "ubuntu2604-arch",
        "Ubuntu 26.04 guest architecture: x86_64 (default) or aarch64",
    ) orelse .x86_64;
    const ubuntu2604_flavor = b.option(
        Ubuntu2604Flavor,
        "ubuntu2604-flavor",
        "Ubuntu 26.04 guest flavor: full (default, cloud-init/systemd), core (mizinit/azagent), or baremetal (core on a physical machine)",
    ) orelse .full;
    const bzip2z = b.dependency("bzip2z", .{
        .target = target,
        .optimize = optimize,
    });
    const host_bzip2z = b.dependency("bzip2z", .{
        .target = b.graph.host,
        .optimize = optimize,
    });
    const debz_dependency = b.dependency("debz", .{
        .target = b.graph.host,
        .optimize = optimize,
    });
    const debz_mod = debz_dependency.module("debz");
    const rpmz_dependency = b.dependency("rpmz", .{
        .target = b.graph.host,
        .optimize = optimize,
    });
    const zstd_dependency = zstdDependency(b, target, optimize);
    const host_zstd_dependency = zstdDependency(b, b.graph.host, optimize);

    // ---- packages/miz: the core disk-image library ----
    const miz_mod = b.addModule("miz", .{
        .root_source_file = b.path("packages/miz/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addZstdLibrary(miz_mod, zstd_dependency);
    const host_miz_mod = b.addModule("miz_host", .{
        .root_source_file = b.path("packages/miz/src/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addZstdLibrary(host_miz_mod, host_zstd_dependency);
    host_miz_mod.addImport("debz", debz_mod);
    const static_host_miz_mod = b.createModule(.{
        .root_source_file = b.path("packages/miz/src/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addZstdHeaders(static_host_miz_mod, host_zstd_dependency);
    const package_family_mod = b.createModule(.{
        .root_source_file = b.path("packages/miz/src/package_family.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "debz", .module = debz_mod }},
    });
    const host_package_family_mod = b.addModule("miz-package-family-host", .{
        .root_source_file = b.path("packages/miz/src/rpm_package_family.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "package_family", .module = package_family_mod },
            .{ .name = "rpmz", .module = rpmz_dependency.module("rpmz") },
        },
    });
    const host_package_family_tests = b.addTest(.{
        .root_module = host_package_family_mod,
    });
    const run_host_package_family_tests = b.addRunArtifact(
        host_package_family_tests,
    );
    const package_family_test_step = b.step(
        "test-package-family-host",
        "Run host-only rpmz package-family tests",
    );
    package_family_test_step.dependOn(&run_host_package_family_tests.step);
    // Declared this early because the preserved-image builder resolves EDK2
    // firmware through the same module `miz qemu` does, and that builder is
    // constructed well before the qemu-facing part of the graph.
    const host_qemu_host_mod = b.createModule(.{
        .root_source_file = b.path("qemu/host.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bzip2z", .module = host_bzip2z.module("bzip2z") },
        },
    });

    const miz_tests = b.addTest(.{ .root_module = host_miz_mod });
    const run_miz_tests = b.addRunArtifact(miz_tests);
    // The miz package's own tests -- image formats, qcow2, ext4, offline root
    // -- are otherwise reachable only through the aggregate `test` step, which
    // makes a targeted change to one of them expensive to verify.
    const miz_test_step = b.step("test-miz", "Run the miz package's tests");
    miz_test_step.dependOn(&run_miz_tests.step);
    const package_family_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("packages/miz/src/package_family.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "debz", .module = debz_mod }},
        }),
    });
    const run_package_family_tests = b.addRunArtifact(package_family_tests);
    b.step("test-package-family", "Run embedded debz package-family acceptance tests")
        .dependOn(&run_package_family_tests.step);
    const tls_fixture = b.dependency("tls", .{
        .target = b.graph.host,
        .optimize = optimize,
    });
    const oci_registry_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/oci_registry.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
                .{ .name = "tls", .module = tls_fixture.module("tls") },
            },
        }),
    });
    const run_oci_registry_tests = b.addRunArtifact(oci_registry_tests);
    const oci_registry_test_step = b.step(
        "test-oci-registry",
        "Run deterministic OCI registry transport tests",
    );
    oci_registry_test_step.dependOn(&run_oci_registry_tests.step);

    // ---- wireserver: native Zig client for the Azure WireServer
    // goal-state protocol (minimal provisioning subset). A self-contained
    // module with no standalone build.zig of its own; consumed by the
    // future `azagent` guest provisioning executable (issue #112). ----
    const wireserver_mod = b.addModule("wireserver", .{
        .root_source_file = b.path("wireserver/wireserver.zig"),
        .target = target,
        .optimize = optimize,
    });

    const wireserver_tests = b.addTest(.{ .root_module = wireserver_mod });
    const run_wireserver_tests = b.addRunArtifact(wireserver_tests);

    // ---- qemu/host.zig: shared host-side QEMU and OVMF discovery ----
    const qemu_host_mod = b.addModule("qemu_host", .{
        .root_source_file = b.path("qemu/host.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bzip2z", .module = bzip2z.module("bzip2z") },
        },
    });
    const guest_validation_mod = b.addModule("guest_validation", .{
        .root_source_file = b.path("azagent/validation.zig"),
        .target = target,
        .optimize = optimize,
    });
    const qemu_host_tests = b.addTest(.{ .root_module = qemu_host_mod });
    const run_qemu_host_tests = b.addRunArtifact(qemu_host_tests);

    // ---- azagent: minimal guest provisioning agent for first-boot Azure
    // VM setup (issue #112). Statically linked for self-containment
    // (matching mizinit's philosophy), but -- unlike mizinit, which is
    // pinned to a single real-boot x86_64 QEMU test fixture -- built for
    // the standard target/optimize so it supports every Linux architecture
    // a given image targets (Azure supports Arm64 VMs too) and remains
    // natively testable via `zig build test` on any host.
    // Imports `miz` too (issue #113's resource-disk setup reuses
    // `mbr.zig`/`ext4.zig` directly against a real block device). ----
    const azagent_miz_mod = b.createModule(.{
        .root_source_file = b.path("packages/miz/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addZstdHeaders(azagent_miz_mod, zstd_dependency);
    const azagent_mod = b.createModule(.{
        .root_source_file = b.path("azagent/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wireserver", .module = wireserver_mod },
            .{ .name = "miz", .module = azagent_miz_mod },
        },
    });

    if (target.result.os.tag == .linux) {
        const azagent_exe = b.addExecutable(.{
            .name = "azagent",
            .root_module = azagent_mod,
            .linkage = .static,
        });
        b.installArtifact(azagent_exe);
        ci_production_entrypoint_check.dependOn(&azagent_exe.step);
    }

    const azagent_tests = b.addTest(.{ .root_module = azagent_mod });
    const run_azagent_tests = b.addRunArtifact(azagent_tests);
    const azagent_test_step = b.step("test-azagent", "Run azagent tests");
    azagent_test_step.dependOn(&run_azagent_tests.step);

    // ---- cli: the `miz` executable ----
    const cli_exe = b.addExecutable(.{
        .name = "miz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = miz_mod },
                .{ .name = "qemu_host", .module = qemu_host_mod },
                .{ .name = "guest_validation", .module = guest_validation_mod },
            },
        }),
    });
    ci_production_entrypoint_check.dependOn(&cli_exe.step);
    const install_cli = b.addInstallArtifact(cli_exe, .{});
    b.getInstallStep().dependOn(&install_cli.step);

    const install_cli_step = b.step("install-miz", "Install only the miz CLI");
    install_cli_step.dependOn(&install_cli.step);

    const run_cmd = b.addRunArtifact(cli_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run miz");
    run_step.dependOn(&run_cmd.step);

    const cli_tests = b.addTest(.{ .root_module = cli_exe.root_module });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    const cli_test_step = b.step("test-cli", "Run miz CLI tests");
    cli_test_step.dependOn(&run_cli_tests.step);

    // Host-only image builders used by the exported build helpers. They remain
    // executable even when the dependency is configured for a foreign target.
    const image_builder_exe = b.addExecutable(.{
        .name = "miz-image-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/image_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
            },
        }),
    });
    b.installArtifact(image_builder_exe);
    ci_production_entrypoint_check.dependOn(&image_builder_exe.step);
    const image_builder_tests = b.addTest(.{
        .root_module = image_builder_exe.root_module,
    });
    const run_image_builder_tests = b.addRunArtifact(image_builder_tests);
    const image_builder_test_step = b.step(
        "test-image-builder",
        "Run the host image builder's argument tests",
    );
    image_builder_test_step.dependOn(&run_image_builder_tests.step);

    // Host-only ISO builder used by the exported `addIso` build helper.
    const iso_builder_exe = b.addExecutable(.{
        .name = "miz-iso-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/iso_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
            },
        }),
    });
    b.installArtifact(iso_builder_exe);
    ci_production_entrypoint_check.dependOn(&iso_builder_exe.step);
    const iso_builder_tests = b.addTest(.{
        .root_module = iso_builder_exe.root_module,
    });
    const run_iso_builder_tests = b.addRunArtifact(iso_builder_tests);
    const iso_builder_test_step = b.step(
        "test-iso-builder",
        "Run the host ISO builder's argument tests",
    );
    iso_builder_test_step.dependOn(&run_iso_builder_tests.step);

    // Host-only recustomize-iso builder used by the exported `addRecustomize`
    // build helper. Kept apart from the iso builder since it drives the strict
    // preserve-or-refuse product and emits a preservation report.
    const recustomize_iso_builder_exe = b.addExecutable(.{
        .name = "miz-recustomize-iso-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/recustomize_iso_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
            },
        }),
    });
    b.installArtifact(recustomize_iso_builder_exe);
    ci_production_entrypoint_check.dependOn(
        &recustomize_iso_builder_exe.step,
    );
    const recustomize_iso_builder_tests = b.addTest(.{
        .root_module = recustomize_iso_builder_exe.root_module,
    });
    const run_recustomize_iso_builder_tests = b.addRunArtifact(recustomize_iso_builder_tests);
    const recustomize_iso_builder_test_step = b.step(
        "test-recustomize-iso-builder",
        "Run the host recustomize-iso builder's argument tests",
    );
    recustomize_iso_builder_test_step.dependOn(&run_recustomize_iso_builder_tests.step);

    const preserved_image_wire_mod = b.createModule(.{
        .root_source_file = b.path("packages/miz/src/preserved_image_wire.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addZstdLibrary(preserved_image_wire_mod, host_zstd_dependency);
    const preserved_image_builder_exe = b.addExecutable(.{
        .name = "miz-preserved-image-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/preserved_image_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
            },
        }),
    });
    b.installArtifact(preserved_image_builder_exe);
    ci_production_entrypoint_check.dependOn(
        &preserved_image_builder_exe.step,
    );
    const preserved_image_builder_tests = b.addTest(.{
        .root_module = preserved_image_builder_exe.root_module,
    });
    const run_preserved_image_builder_tests = b.addRunArtifact(
        preserved_image_builder_tests,
    );
    const preserved_image_wire_tests = b.addTest(.{
        .root_module = preserved_image_wire_mod,
    });
    const run_preserved_image_wire_tests = b.addRunArtifact(
        preserved_image_wire_tests,
    );
    const preserved_image_builder_test_step = b.step(
        "test-preserved-image-builder",
        "Run preserved-image host builder and wire tests",
    );
    preserved_image_builder_test_step.dependOn(
        &run_preserved_image_builder_tests.step,
    );
    preserved_image_builder_test_step.dependOn(
        &run_preserved_image_wire_tests.step,
    );

    const input_validator_mod = b.createModule(.{
        .root_source_file = b.path("cli/src/input_validator.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const input_validator_exe = b.addExecutable(.{
        .name = "miz-input-validator",
        .root_module = input_validator_mod,
    });
    b.installArtifact(input_validator_exe);
    ci_production_entrypoint_check.dependOn(&input_validator_exe.step);
    const input_validator_tests = b.addTest(.{ .root_module = input_validator_mod });
    const run_input_validator_tests = b.addRunArtifact(input_validator_tests);

    const image_status_check_mod = b.createModule(.{
        .root_source_file = b.path("cli/src/image_status_check.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const image_status_check_exe = b.addExecutable(.{
        .name = "miz-image-status-check",
        .root_module = image_status_check_mod,
    });
    b.installArtifact(image_status_check_exe);
    ci_production_entrypoint_check.dependOn(&image_status_check_exe.step);
    const image_status_check_tests = b.addTest(.{ .root_module = image_status_check_mod });
    const run_image_status_check_tests = b.addRunArtifact(image_status_check_tests);

    // ---- qmp: native Zig QEMU Machine Protocol (QMP) client ----
    const qmp_mod = b.addModule("qmp", .{
        .root_source_file = b.path("qmp/src/qmp.zig"),
        .target = target,
    });

    const qmp_exe = b.addExecutable(.{
        .name = "qmp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("qmp/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "qmp", .module = qmp_mod },
            },
        }),
    });
    b.installArtifact(qmp_exe);
    ci_production_entrypoint_check.dependOn(&qmp_exe.step);

    // Offline QAPI-schema-to-Zig-bindings generator. Not part of the default
    // build graph's dependency chain on qapi/*.json; run manually against a
    // QEMU checkout (see qmp/README.md) and commit the generated
    // qmp/src/qapi_generated.zig.
    const qapi_codegen_exe = b.addExecutable(.{
        .name = "qapi-codegen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("qmp/tools/qapi_codegen.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(qapi_codegen_exe);
    ci_production_entrypoint_check.dependOn(&qapi_codegen_exe.step);

    const run_qapi_codegen = b.addRunArtifact(qapi_codegen_exe);
    run_qapi_codegen.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_qapi_codegen.addArgs(args);
    const qapi_codegen_step = b.step("qapi-codegen", "Regenerate qmp/src/qapi_generated.zig from a QEMU checkout's qapi/qapi-schema.json");
    qapi_codegen_step.dependOn(&run_qapi_codegen.step);

    const qmp_mod_tests = b.addTest(.{ .root_module = qmp_mod });
    const run_qmp_mod_tests = b.addRunArtifact(qmp_mod_tests);
    const qmp_exe_tests = b.addTest(.{ .root_module = qmp_exe.root_module });
    const run_qmp_exe_tests = b.addRunArtifact(qmp_exe_tests);
    const qmp_codegen_tests = b.addTest(.{ .root_module = qapi_codegen_exe.root_module });
    const run_qmp_codegen_tests = b.addRunArtifact(qmp_codegen_tests);
    // `qmp/tools/qapi_schema.zig`'s tests aren't reachable from
    // `qapi_codegen.zig` as a *test* root (Zig only auto-discovers `test`
    // blocks declared in the module's own root file), so it needs its own
    // test root too.
    const qmp_schema_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("qmp/tools/qapi_schema.zig"),
        .target = target,
    }) });
    const run_qmp_schema_tests = b.addRunArtifact(qmp_schema_tests);

    // ---- tests/boot_smoke.zig: opportunistic real-QEMU boot verification,
    // driving miz.build_image.build() output with qmp. Lives outside
    // packages/miz since it needs both miz and qmp -- see issue #99. ----
    const boot_smoke_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/boot_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "miz", .module = miz_mod },
            .{ .name = "qmp", .module = qmp_mod },
            .{ .name = "qemu_host", .module = qemu_host_mod },
        },
    }) });
    const run_boot_smoke_tests = b.addRunArtifact(boot_smoke_tests);
    const boot_smoke_step = b.step("test-boot-smoke", "Run opportunistic real-QEMU boot-smoke tests");
    boot_smoke_step.dependOn(&run_boot_smoke_tests.step);

    const device_write_integration_exe = b.addExecutable(.{
        .name = "miz-device-write-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/device_write_integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = static_host_miz_mod },
            },
        }),
        .linkage = .static,
    });
    const run_device_write_integration = b.addRunArtifact(
        device_write_integration_exe,
    );
    run_device_write_integration.addArtifactArg(cli_exe);
    const device_write_integration_step = b.step(
        "test-device-write-integration",
        "Run miz write against real sparse loop devices",
    );
    device_write_integration_step.dependOn(
        &run_device_write_integration.step,
    );

    const unsafe_chroot_integration_exe = b.addExecutable(.{
        .name = "miz-unsafe-chroot-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unsafe_chroot_integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = static_host_miz_mod },
            },
        }),
        .linkage = .static,
    });
    const run_unsafe_chroot_integration = b.addRunArtifact(
        unsafe_chroot_integration_exe,
    );
    const unsafe_chroot_integration_step = b.step(
        "test-unsafe-chroot-integration",
        "Run the privileged unsafe-chroot lifecycle integration",
    );
    unsafe_chroot_integration_step.dependOn(
        &run_unsafe_chroot_integration.step,
    );

    const vm_backend_integration_exe = b.addExecutable(.{
        .name = "miz-vm-backend-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/vm_backend_integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = static_host_miz_mod },
            },
        }),
        .linkage = .static,
    });
    const run_vm_backend_integration = b.addRunArtifact(
        vm_backend_integration_exe,
    );
    const vm_backend_integration_step = b.step(
        "test-vm-backend",
        "Run the vm backend lifecycle against a stand-in emulator",
    );
    vm_backend_integration_step.dependOn(&run_vm_backend_integration.step);

    const vm_real_boot_exe = b.addExecutable(.{
        .name = "miz-vm-real-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/vm_real_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = static_host_miz_mod },
            },
        }),
        .linkage = .static,
    });
    const run_vm_real_boot = b.addRunArtifact(vm_real_boot_exe);
    const vm_real_boot_step = b.step(
        "test-vm-real-boot",
        "Boot a real guest in a real emulator on a supplied kernel",
    );
    vm_real_boot_step.dependOn(&run_vm_real_boot.step);

    // Not part of `zig build test`: it needs a bootable image and real EDK2
    // firmware, neither of which a test run may assume.
    const vm_firmware_boot_exe = b.addExecutable(.{
        .name = "miz-vm-firmware-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/vm_firmware_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = miz_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
            },
        }),
    });
    const run_vm_firmware_boot = b.addRunArtifact(vm_firmware_boot_exe);
    const vm_firmware_boot_step = b.step(
        "test-vm-firmware-boot",
        "Attest a supplied bootable image through real EDK2 firmware",
    );
    vm_firmware_boot_step.dependOn(&run_vm_firmware_boot.step);

    const host_qmp_mod = b.createModule(.{
        .root_source_file = b.path("qmp/src/qmp.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    // The FreeBSD package manifests are shared by the builder that realizes
    // them and the acceptance test that verifies a booted image against them,
    // so both import the same module rather than restating the contract.
    const freebsd_packages_mod = b.createModule(.{
        .root_source_file = b.path("scripts/freebsd15_package_manifest.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const freebsd_boot_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/freebsd15_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "qmp", .module = host_qmp_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
                .{ .name = "packages", .module = freebsd_packages_mod },
                .{ .name = "miz", .module = host_miz_mod },
            },
        }),
    });
    const run_freebsd_boot_tests = b.addRunArtifact(freebsd_boot_tests);
    const freebsd_boot_test_step = b.step(
        "test-freebsd15-boot",
        "Run opt-in generalized FreeBSD 15.1 QEMU acceptance",
    );
    freebsd_boot_test_step.dependOn(&run_freebsd_boot_tests.step);
    const freebsd_aarch64_boot_test_step = b.step(
        "test-freebsd15-aarch64-boot",
        "Run opt-in generalized FreeBSD 15.1 AArch64 QEMU acceptance",
    );
    freebsd_aarch64_boot_test_step.dependOn(&run_freebsd_boot_tests.step);

    // ---- scripts/release: the shared foundation the Zig release tooling is
    // built on -- failure diagnostics, bounded reads, atomic output staging,
    // streaming SHA-256, and strict/canonical JSON documents. It is pure host
    // code with no external tools behind it, so it builds and tests
    // everywhere. ----
    const release_support_mod = b.createModule(.{
        .root_source_file = b.path("scripts/release/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const release_support_tests = b.addTest(.{
        .root_module = release_support_mod,
    });
    const run_release_support_tests = b.addRunArtifact(release_support_tests);
    const release_support_test_step = b.step(
        "test-release-support",
        "Run shared release-tooling foundation unit tests",
    );
    release_support_test_step.dependOn(&run_release_support_tests.step);

    // ---- scripts/azure_vhd.zig: fixed-VHD footer, geometry, and qemu-img
    // agreement checks for Azure uploads, replacing scripts/azure_vhd.py.
    // Validation only, so it is host-native everywhere the release jobs run.
    const azure_vhd_mod = b.createModule(.{
        .root_source_file = b.path("scripts/azure_vhd.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "miz", .module = host_miz_mod },
        },
    });
    const azure_vhd_exe = b.addExecutable(.{
        .name = "azure_vhd",
        .root_module = azure_vhd_mod,
    });
    b.installArtifact(azure_vhd_exe);
    const azure_vhd_tests = b.addTest(.{ .root_module = azure_vhd_mod });
    const run_azure_vhd_tests = b.addRunArtifact(azure_vhd_tests);
    const azure_vhd_test_step = b.step(
        "test-azure-vhd",
        "Run Azure fixed-VHD validation unit tests",
    );
    azure_vhd_test_step.dependOn(&run_azure_vhd_tests.step);

    // ---- tests/python_inventory.zig: the temporary, explicit inventory of
    // the Python this repository still owns. It shells out to `git ls-files`
    // and reads the tracked tree, so its result is never cacheable. ----
    const python_inventory_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/python_inventory.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run_python_inventory_tests = b.addRunArtifact(python_inventory_tests);
    // The inventory's subject is the tracked tree, which is not an input the
    // build graph models, so a cached result would speak for a tree that has
    // since changed.
    run_python_inventory_tests.has_side_effects = true;
    // Naming the build root outright keeps the inventory independent of the
    // directory the test binary happens to be started in, matching the stale
    // brand guard.
    run_python_inventory_tests.setEnvironmentVariable(
        "MIZ_PYTHON_INVENTORY_ROOT",
        b.build_root.path orelse ".",
    );
    const python_inventory_step = b.step(
        "test-python-inventory",
        "Check the temporary inventory of repository-owned Python",
    );
    python_inventory_step.dependOn(&run_python_inventory_tests.step);
    const unsafe_chroot_real_boot_exe = b.addExecutable(.{
        .name = "miz-unsafe-chroot-real-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unsafe_chroot_real_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = miz_mod },
                .{ .name = "qmp", .module = host_qmp_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
            },
        }),
        .linkage = .static,
    });
    const run_unsafe_chroot_real_boot = b.addRunArtifact(
        unsafe_chroot_real_boot_exe,
    );
    const unsafe_chroot_real_boot_step = b.step(
        "test-unsafe-chroot-real-boot",
        "Run real TDNF/dracut customization and QEMU boot integration",
    );
    unsafe_chroot_real_boot_step.dependOn(
        &run_unsafe_chroot_real_boot.step,
    );

    // ---- nbd: native Zig NBD client + reference server ----
    const nbd_mod = b.addModule("nbd", .{
        .root_source_file = b.path("nbd/src/nbd.zig"),
        .target = target,
    });

    const nbd_exe = b.addExecutable(.{
        .name = "nbd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("nbd/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nbd", .module = nbd_mod },
            },
        }),
    });
    b.installArtifact(nbd_exe);
    ci_production_entrypoint_check.dependOn(&nbd_exe.step);

    const nbd_mod_tests = b.addTest(.{ .root_module = nbd_mod });
    const run_nbd_mod_tests = b.addRunArtifact(nbd_mod_tests);
    const nbd_exe_tests = b.addTest(.{ .root_module = nbd_exe.root_module });
    const run_nbd_exe_tests = b.addRunArtifact(nbd_exe_tests);
    // `nbd/src/server.zig`'s tests aren't reachable from `nbd/src/nbd.zig`
    // as a *test* root (Zig only auto-discovers `test` blocks declared in
    // the module's own root file), even though `nbd.zig` re-exports it as
    // `nbd.server`, so it needs its own test root too.
    const nbd_server_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("nbd/src/server.zig"),
        .target = target,
    }) });
    const run_nbd_server_tests = b.addRunArtifact(nbd_server_tests);

    // ---- qcow2: native Zig qcow2 reader/writer ----
    const qcow2_mod = b.addModule("qcow2", .{
        .root_source_file = b.path("qcow2/src/qcow2.zig"),
        .target = target,
    });

    const qcow2_exe = b.addExecutable(.{
        .name = "qcow2",
        .root_module = b.createModule(.{
            .root_source_file = b.path("qcow2/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "qcow2", .module = qcow2_mod },
            },
        }),
    });
    b.installArtifact(qcow2_exe);
    ci_production_entrypoint_check.dependOn(&qcow2_exe.step);

    const qcow2_mod_tests = b.addTest(.{ .root_module = qcow2_mod });
    const run_qcow2_mod_tests = b.addRunArtifact(qcow2_mod_tests);
    const qcow2_exe_tests = b.addTest(.{ .root_module = qcow2_exe.root_module });
    const run_qcow2_exe_tests = b.addRunArtifact(qcow2_exe_tests);

    // ---- mizinit: standalone minimal PID 1 for generalized Azure Linux
    // core images. Its guest target follows -Dazurelinux-arch, while the
    // ordinary CLI, builder, and preload library remain host-native. ----
    const mizinit_target = b.resolveTargetQuery(.{
        .cpu_arch = switch (azurelinux_architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .os_tag = .linux,
    });
    const mizinit_cdrom_mod = b.createModule(.{
        .root_source_file = b.path("azagent/cdrom.zig"),
        .target = mizinit_target,
        .optimize = .ReleaseSmall,
    });
    const mizinit_mod = b.createModule(.{
        .root_source_file = b.path("mizinit/init.zig"),
        .target = mizinit_target,
        .optimize = .ReleaseSmall,
        .imports = &.{
            .{ .name = "provisioning_media", .module = mizinit_cdrom_mod },
        },
    });
    const mizinit_exe = b.addExecutable(.{
        .name = "mizinit",
        .root_module = mizinit_mod,
        .linkage = .static,
    });
    b.installArtifact(mizinit_exe);

    const mizinit_test_cdrom_mod = b.createModule(.{
        .root_source_file = b.path("azagent/cdrom.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mizinit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("mizinit/init.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "provisioning_media", .module = mizinit_test_cdrom_mod },
            },
        }),
    });
    const run_mizinit_tests = b.addRunArtifact(mizinit_tests);
    const mizinit_test_step = b.step("test-mizinit", "Run mizinit tests");
    mizinit_test_step.dependOn(&run_mizinit_tests.step);

    // ---- mizguest: the static, libc-free PID 1 that the vm customization
    // backend appends to the target image's own initramfs. It is built for
    // every architecture the backend can drive a guest at, not just the host's,
    // because cross-architecture customization is the point. ----
    const guest_architectures = [_]std.Target.Cpu.Arch{ .x86_64, .aarch64 };
    const mizguest_step = b.step(
        "mizguest",
        "Build the in-VM guest agent for every supported guest architecture",
    );
    for (guest_architectures) |architecture| {
        const guest_target = b.resolveTargetQuery(.{
            .cpu_arch = architecture,
            .os_tag = .linux,
        });
        const guest_control_mod = b.createModule(.{
            .root_source_file = b.path("packages/miz/src/vm_control.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
        });
        const mizguest_exe = b.addExecutable(.{
            .name = b.fmt("miz-guest-agent-{s}", .{@tagName(architecture)}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("mizguest/main.zig"),
                .target = guest_target,
                .optimize = .ReleaseSmall,
                .imports = &.{
                    .{ .name = "vm_control", .module = guest_control_mod },
                },
            }),
            .linkage = .static,
        });
        b.installArtifact(mizguest_exe);
        mizguest_step.dependOn(&mizguest_exe.step);
        // The builder embeds every agent rather than locating one on disk at
        // run time, so the bytes that boot a guest are the bytes this build
        // produced and provenance can name them without qualification.
        preserved_image_builder_exe.root_module.addAnonymousImport(
            b.fmt("miz_guest_agent_{s}", .{@tagName(architecture)}),
            .{ .root_source_file = mizguest_exe.getEmittedBin() },
        );
        vm_real_boot_exe.root_module.addAnonymousImport(
            b.fmt("miz_guest_agent_{s}", .{@tagName(architecture)}),
            .{ .root_source_file = mizguest_exe.getEmittedBin() },
        );

        // The stand-in for `rpm` runs inside the guest, so it is built for the
        // guest's architecture rather than re-entered from the test binary,
        // which a cross-architecture guest could not execute.
        const guest_stub_exe = b.addExecutable(.{
            .name = b.fmt("miz-vm-guest-stub-{s}", .{@tagName(architecture)}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/vm_guest_stub.zig"),
                .target = guest_target,
                .optimize = .ReleaseSmall,
            }),
            .linkage = .static,
        });
        vm_real_boot_exe.root_module.addAnonymousImport(
            b.fmt("vm_guest_stub_{s}", .{@tagName(architecture)}),
            .{ .root_source_file = guest_stub_exe.getEmittedBin() },
        );
    }

    const mizguest_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("mizguest/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vm_control", .module = b.createModule(.{
                    .root_source_file = b.path("packages/miz/src/vm_control.zig"),
                    .target = target,
                    .optimize = optimize,
                }) },
            },
        }),
    });
    const run_mizguest_tests = b.addRunArtifact(mizguest_tests);
    const mizguest_test_step = b.step("test-mizguest", "Run guest agent tests");
    mizguest_test_step.dependOn(&run_mizguest_tests.step);

    const test_step = b.step("test", "Run all tests");
    const ci_test_step = b.step(
        "test-ci",
        "Run CI tests except integrations assigned to dedicated jobs",
    );
    const aggregate_test_steps = [_]*std.Build.Step{
        test_step,
        ci_test_step,
    };

    // ---- tests/stale_brand.zig: the tracked tree may carry only the
    // canonical brand -- in path names, in file bytes, and in the DER
    // metadata of the certificates the `.pem` fixtures hold. Replaces
    // tests/stale_brand_test.py. ----
    const stale_brand_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/stale_brand.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run_stale_brand_tests = b.addRunArtifact(stale_brand_tests);
    // The guard's subject is the tracked tree, which is not an input the
    // build graph models, so a cached result would speak for a tree that has
    // since changed.
    run_stale_brand_tests.has_side_effects = true;
    // Naming the build root outright keeps the guard independent of the
    // directory the test binary happens to be started in.
    run_stale_brand_tests.setEnvironmentVariable(
        "MIZ_STALE_BRAND_ROOT",
        b.build_root.path orelse ".",
    );
    const stale_brand_test_step = b.step(
        "test-stale-brand",
        "Check the tracked tree for legacy branding",
    );
    stale_brand_test_step.dependOn(&run_stale_brand_tests.step);

    const build_api_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("build.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run_build_api_tests = b.addRunArtifact(build_api_tests);
    const build_api_test_step = b.step(
        "test-build-api",
        "Run exported build API unit tests",
    );
    build_api_test_step.dependOn(&run_build_api_tests.step);

    const build_api_consumer_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "package-family",
    });
    build_api_consumer_check.setName("check external build.zig consumer");
    build_api_consumer_check.setCwd(b.path("tests/build_api_consumer"));

    const package_family_consumer_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "check",
    });
    package_family_consumer_check.setName(
        "check external host package-family consumer",
    );
    package_family_consumer_check.setCwd(
        b.path("tests/package_family_consumer"),
    );

    const build_api_diagnostics_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "diagnostics",
    });
    build_api_diagnostics_check.setName("check external build.zig diagnostics");
    build_api_diagnostics_check.setCwd(b.path("tests/build_api_consumer"));

    const build_api_execution_diagnostics_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "execution-diagnostics",
    });
    build_api_execution_diagnostics_check.setName("check external build.zig execution diagnostics");
    build_api_execution_diagnostics_check.setCwd(b.path("tests/build_api_consumer"));

    const build_api_preserved_diagnostics_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "preserved-diagnostics",
    });
    build_api_preserved_diagnostics_check.setName(
        "check external preserved-image build.zig diagnostics",
    );
    build_api_preserved_diagnostics_check.setCwd(b.path("tests/build_api_consumer"));

    const build_api_preserved_vm_diagnostics_check = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "preserved-vm-diagnostics",
    });
    build_api_preserved_vm_diagnostics_check.setName(
        "check external preserved-image vm backend diagnostics",
    );
    build_api_preserved_vm_diagnostics_check.setCwd(b.path("tests/build_api_consumer"));

    // ---- scripts/build_generalized_azurelinux4.zig: generalized Azure Linux 4
    // QCOW2 builder, replacing scripts/build-generalized-azurelinux4.py.
    // Linux-specific: the full pipeline (dnf, sudo chroot, qemu-img) is only
    // meaningful on Linux.  The zstd_max_preload shared library is also
    // Linux-specific. ----
    if (b.graph.host.result.os.tag == .linux) {
        const guest_zstd_dependency = zstdDependency(b, mizinit_target, .ReleaseSmall);

        // Guest-targeted azagent for embedding in the generalized image.
        // It follows -Dazurelinux-arch and is static/ReleaseSmall, matching
        // mizinit.
        const miz_guest_mod = b.createModule(.{
            .root_source_file = b.path("packages/miz/src/root.zig"),
            .target = mizinit_target,
            .optimize = .ReleaseSmall,
        });
        addZstdHeaders(miz_guest_mod, guest_zstd_dependency);
        const wireserver_guest_mod = b.createModule(.{
            .root_source_file = b.path("wireserver/wireserver.zig"),
            .target = mizinit_target,
            .optimize = .ReleaseSmall,
        });
        const azagent_guest_mod = b.createModule(.{
            .root_source_file = b.path("azagent/main.zig"),
            .target = mizinit_target,
            .optimize = .ReleaseSmall,
            .imports = &.{
                .{ .name = "wireserver", .module = wireserver_guest_mod },
                .{ .name = "miz", .module = miz_guest_mod },
            },
        });
        const azagent_guest_exe = b.addExecutable(.{
            .name = "azagent",
            .root_module = azagent_guest_mod,
            .linkage = .static,
        });

        // LD_PRELOAD shared library: intercepts ZSTD_compressStream2 and sets
        // ZSTD_maxCLevel() so qemu-img -o compression_type=zstd uses max compression.
        const zstd_preload_lib = b.addLibrary(.{
            .name = "zstd_max_preload",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("scripts/zstd_max_preload.zig"),
                .target = b.graph.host,
                .optimize = .ReleaseFast,
                .link_libc = true,
            }),
        });
        // Link libdl for dlsym; libzstd is resolved at runtime via dlsym(RTLD_NEXT).
        zstd_preload_lib.root_module.linkSystemLibrary("dl", .{});
        b.installArtifact(zstd_preload_lib);

        const builder_mod = b.createModule(.{
            .root_source_file = b.path("scripts/build_generalized_azurelinux4.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
            },
        });
        const builder_exe = b.addExecutable(.{
            .name = "build_generalized_azurelinux4",
            .root_module = builder_mod,
        });
        b.installArtifact(builder_exe);

        // Compile the complete selected-guest artifact set without executing
        // the privileged image pipeline. This is also useful on an x86_64
        // development host to verify the AArch64 cross-build graph.
        const generalized_check_step = b.step(
            "check-generalized-azurelinux4",
            "Compile the selected Azure Linux flavor builder and required guest artifacts",
        );
        generalized_check_step.dependOn(&builder_exe.step);
        if (azurelinux_flavor == .core) {
            generalized_check_step.dependOn(&mizinit_exe.step);
            generalized_check_step.dependOn(&azagent_guest_exe.step);
        }
        generalized_check_step.dependOn(&zstd_preload_lib.step);

        // `zig build generalized-azurelinux4 -- [--iso ...] [--output ...] ...`
        // Automatically passes the paths of the just-built native miz, guest
        // mizinit/azagent, and the preload library so the builder does not need to
        // invoke `zig build` itself.
        const run_builder = b.addRunArtifact(builder_exe);
        run_builder.step.dependOn(b.getInstallStep());
        run_builder.addArg("--architecture");
        run_builder.addArg(@tagName(azurelinux_architecture));
        run_builder.addArg("--flavor");
        run_builder.addArg(@tagName(azurelinux_flavor));
        run_builder.addArg("--miz");
        run_builder.addArtifactArg(cli_exe);
        if (azurelinux_flavor == .core) {
            run_builder.addArg("--mizinit");
            run_builder.addArtifactArg(mizinit_exe);
            run_builder.addArg("--azagent");
            run_builder.addArtifactArg(azagent_guest_exe);
        }
        run_builder.addArg("--preload");
        run_builder.addArtifactArg(zstd_preload_lib);
        if (b.args) |args| run_builder.addArgs(args);
        const generalized_step = b.step(
            "generalized-azurelinux4",
            "Build a generalized Azure Linux 4 Gen2 core or full QCOW2 image (requires root, Linux, dnf, qemu-img)",
        );
        generalized_step.dependOn(&run_builder.step);

        // Tests for pure, side-effect-free helpers.
        const builder_tests = b.addTest(.{
            .root_module = builder_mod,
        });
        const run_builder_tests = b.addRunArtifact(builder_tests);
        const builder_test_step = b.step("test-generalized-azurelinux4", "Run build_generalized_azurelinux4 unit tests");
        builder_test_step.dependOn(&run_builder_tests.step);
        for (aggregate_test_steps) |aggregate_test_step| {
            aggregate_test_step.dependOn(&run_builder_tests.step);
            aggregate_test_step.dependOn(generalized_check_step);
        }

        // ---- Ubuntu 26.04: immutable Canonical cloud-image input, Azure
        // package customization, host-side signed UKI, and standalone zstd
        // QCOW2 finalization. The builder is host-native for both guest
        // architectures and uses the offline-root mount namespace. ----
        const ubuntu2604_builder_mod = b.createModule(.{
            .root_source_file = b.path("scripts/build_generalized_ubuntu2604.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
            },
        });
        const ubuntu2604_builder_exe = b.addExecutable(.{
            .name = "build_generalized_ubuntu2604",
            .root_module = ubuntu2604_builder_mod,
        });
        b.installArtifact(ubuntu2604_builder_exe);
        const ubuntu2604_core_x86_64 = if (ubuntu2604_flavor.needsGuestArtifacts())
            addUbuntu2604CoreArtifacts(b, .x86_64)
        else
            null;
        const ubuntu2604_core_aarch64 = if (ubuntu2604_flavor.needsGuestArtifacts())
            addUbuntu2604CoreArtifacts(b, .aarch64)
        else
            null;
        const selected_ubuntu2604_core = switch (ubuntu2604_architecture) {
            .x86_64 => ubuntu2604_core_x86_64,
            .aarch64 => ubuntu2604_core_aarch64,
        };

        const ubuntu2604_check = b.step(
            "check-generalized-ubuntu2604",
            "Compile the Ubuntu 26.04 builder and selected core guest artifacts",
        );
        ubuntu2604_check.dependOn(&ubuntu2604_builder_exe.step);
        if (selected_ubuntu2604_core) |artifacts| {
            ubuntu2604_check.dependOn(&artifacts.mizinit.step);
            ubuntu2604_check.dependOn(&artifacts.azagent.step);
        }

        const ubuntu2604_tests = b.addTest(.{
            .root_module = ubuntu2604_builder_mod,
        });
        const run_ubuntu2604_tests = b.addRunArtifact(ubuntu2604_tests);
        const ubuntu2604_test_step = b.step(
            "test-generalized-ubuntu2604",
            "Run focused Ubuntu 26.04 builder tests",
        );
        ubuntu2604_test_step.dependOn(&run_ubuntu2604_tests.step);
        for (aggregate_test_steps) |aggregate_test_step| {
            aggregate_test_step.dependOn(&run_ubuntu2604_tests.step);
            aggregate_test_step.dependOn(ubuntu2604_check);
        }

        const run_ubuntu2604 = b.addRunArtifact(ubuntu2604_builder_exe);
        run_ubuntu2604.addArgs(&.{
            "--architecture", @tagName(ubuntu2604_architecture),
            "--flavor",       @tagName(ubuntu2604_flavor),
        });
        if (selected_ubuntu2604_core) |artifacts| {
            run_ubuntu2604.addArg("--mizinit");
            run_ubuntu2604.addArtifactArg(artifacts.mizinit);
            run_ubuntu2604.addArg("--azagent");
            run_ubuntu2604.addArtifactArg(artifacts.azagent);
        }
        if (b.args) |args| run_ubuntu2604.addArgs(args);
        const ubuntu2604_step = b.step(
            "generalized-ubuntu2604",
            "Build the selected generalized Ubuntu 26.04 Gen2 QCOW2 image",
        );
        ubuntu2604_step.dependOn(&run_ubuntu2604.step);

        inline for (.{ Ubuntu2604Architecture.x86_64, Ubuntu2604Architecture.aarch64 }) |architecture| {
            const run_arch = b.addRunArtifact(ubuntu2604_builder_exe);
            run_arch.addArgs(&.{
                "--architecture", @tagName(architecture),
                "--flavor",       @tagName(ubuntu2604_flavor),
            });
            const core_artifacts = switch (architecture) {
                .x86_64 => ubuntu2604_core_x86_64,
                .aarch64 => ubuntu2604_core_aarch64,
            };
            if (core_artifacts) |artifacts| {
                run_arch.addArg("--mizinit");
                run_arch.addArtifactArg(artifacts.mizinit);
                run_arch.addArg("--azagent");
                run_arch.addArtifactArg(artifacts.azagent);
            }
            if (b.args) |args| run_arch.addArgs(args);
            const step_name = switch (architecture) {
                .x86_64 => "generalized-ubuntu2604-amd64",
                .aarch64 => "generalized-ubuntu2604-arm64",
            };
            const step_description = switch (architecture) {
                .x86_64 => "Build generalized Ubuntu 26.04 for x86_64/amd64",
                .aarch64 => "Build generalized Ubuntu 26.04 for arm64/aarch64",
            };
            b.step(step_name, step_description).dependOn(&run_arch.step);
        }

        // Opt-in native-QEMU acceptance for a completed, finalized release
        // candidate. The image itself is intentionally supplied at runtime:
        // four native matrix entries select their architecture/flavor here and
        // set MIZ_AZURELINUX4_IMAGE to the exact candidate under test.
        const azurelinux_acceptance_options = b.addOptions();
        azurelinux_acceptance_options.addOption(
            []const u8,
            "azurelinux_architecture",
            @tagName(azurelinux_architecture),
        );
        azurelinux_acceptance_options.addOption(
            []const u8,
            "azurelinux_flavor",
            @tagName(azurelinux_flavor),
        );
        const azurelinux_acceptance_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/azurelinux4_acceptance.zig"),
                .target = b.graph.host,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = azurelinux_acceptance_options.createModule() },
                    .{ .name = "qemu_host", .module = host_qemu_host_mod },
                    .{ .name = "qmp", .module = host_qmp_mod },
                    .{ .name = "miz", .module = host_miz_mod },
                },
            }),
        });
        const run_azurelinux_acceptance_tests = b.addRunArtifact(
            azurelinux_acceptance_tests,
        );
        const azurelinux_acceptance_step = b.step(
            "test-azurelinux4-acceptance",
            "Run native-QEMU acceptance for one finalized Azure Linux 4 core or full QCOW2",
        );
        azurelinux_acceptance_step.dependOn(&run_azurelinux_acceptance_tests.step);

        // Opt-in native-QEMU acceptance for exactly one finalized Ubuntu
        // 26.04 full or core candidate. The runtime image and signing identity
        // are supplied externally.
        const ubuntu2604_acceptance_options = b.addOptions();
        ubuntu2604_acceptance_options.addOption(
            []const u8,
            "ubuntu2604_architecture",
            @tagName(ubuntu2604_architecture),
        );
        ubuntu2604_acceptance_options.addOption(
            []const u8,
            "ubuntu2604_flavor",
            @tagName(ubuntu2604_flavor),
        );
        // Binder device usability is a core-only native acceptance contract,
        // so the probe is only cross-built for the core flavor; the option
        // resolves to an empty path otherwise and the acceptance test never
        // reads it in that case.
        if (ubuntu2604_flavor == .core) {
            const ubuntu2604_binder_probe = addUbuntu2604BinderProbe(b, ubuntu2604_architecture);
            ubuntu2604_acceptance_options.addOptionPath(
                "ubuntu2604_binder_probe_path",
                ubuntu2604_binder_probe.getEmittedBin(),
            );
        } else {
            ubuntu2604_acceptance_options.addOption(
                []const u8,
                "ubuntu2604_binder_probe_path",
                "",
            );
        }
        const ubuntu2604_acceptance_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/ubuntu2604_acceptance.zig"),
                .target = b.graph.host,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = ubuntu2604_acceptance_options.createModule() },
                    .{ .name = "qemu_host", .module = host_qemu_host_mod },
                    .{ .name = "qmp", .module = host_qmp_mod },
                    .{ .name = "miz", .module = host_miz_mod },
                },
            }),
        });
        const run_ubuntu2604_acceptance_tests = b.addRunArtifact(
            ubuntu2604_acceptance_tests,
        );
        const ubuntu2604_acceptance_step = b.step(
            "test-ubuntu2604-acceptance",
            "Run native-QEMU acceptance for one finalized Ubuntu 26.04 full or core QCOW2",
        );
        ubuntu2604_acceptance_step.dependOn(&run_ubuntu2604_acceptance_tests.step);

        const freebsd_builder_mod = b.createModule(.{
            .root_source_file = b.path("scripts/build_generalized_freebsd15.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "miz", .module = host_miz_mod },
                .{ .name = "qmp", .module = host_qmp_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
            },
        });
        const freebsd_builder_exe = b.addExecutable(.{
            .name = "build_generalized_freebsd15",
            .root_module = freebsd_builder_mod,
        });
        b.installArtifact(freebsd_builder_exe);
        ci_production_entrypoint_check.dependOn(&freebsd_builder_exe.step);

        const run_freebsd_builder = b.addRunArtifact(freebsd_builder_exe);
        if (b.args) |args| run_freebsd_builder.addArgs(args);
        const generalized_freebsd_step = b.step(
            "generalized-freebsd15",
            "Build a generalized FreeBSD 15.1 QCOW2 (Linux, QEMU, UEFI)",
        );
        generalized_freebsd_step.dependOn(&run_freebsd_builder.step);
        const generalized_freebsd_aarch64_step = b.step(
            "generalized-freebsd15-aarch64",
            "Build a generalized FreeBSD 15.1 AArch64 QCOW2 (Linux, QEMU, UEFI)",
        );
        generalized_freebsd_aarch64_step.dependOn(&run_freebsd_builder.step);

        const freebsd_builder_tests = b.addTest(.{
            .root_module = freebsd_builder_mod,
        });
        const run_freebsd_builder_tests = b.addRunArtifact(
            freebsd_builder_tests,
        );
        const freebsd_builder_test_step = b.step(
            "test-generalized-freebsd15",
            "Run FreeBSD 15.1 builder unit tests",
        );
        freebsd_builder_test_step.dependOn(&run_freebsd_builder_tests.step);
        const freebsd_aarch64_builder_test_step = b.step(
            "test-generalized-freebsd15-aarch64",
            "Run FreeBSD 15.1 builder unit tests",
        );
        freebsd_aarch64_builder_test_step.dependOn(
            &run_freebsd_builder_tests.step,
        );
        for (aggregate_test_steps) |aggregate_test_step| {
            aggregate_test_step.dependOn(&run_freebsd_builder_tests.step);
        }
    }

    for (aggregate_test_steps) |aggregate_test_step| {
        aggregate_test_step.dependOn(&run_miz_tests.step);
        aggregate_test_step.dependOn(&run_host_package_family_tests.step);
        aggregate_test_step.dependOn(&run_oci_registry_tests.step);
        aggregate_test_step.dependOn(&run_wireserver_tests.step);
        aggregate_test_step.dependOn(&run_qemu_host_tests.step);
        aggregate_test_step.dependOn(&run_azagent_tests.step);
        aggregate_test_step.dependOn(&run_cli_tests.step);
        aggregate_test_step.dependOn(&run_image_builder_tests.step);
        aggregate_test_step.dependOn(&run_preserved_image_builder_tests.step);
        aggregate_test_step.dependOn(&run_preserved_image_wire_tests.step);
        aggregate_test_step.dependOn(&run_input_validator_tests.step);
        aggregate_test_step.dependOn(&run_image_status_check_tests.step);
        aggregate_test_step.dependOn(&run_qmp_mod_tests.step);
        aggregate_test_step.dependOn(&run_qmp_exe_tests.step);
        aggregate_test_step.dependOn(&run_qmp_codegen_tests.step);
        aggregate_test_step.dependOn(&run_qmp_schema_tests.step);
        aggregate_test_step.dependOn(&run_boot_smoke_tests.step);
        aggregate_test_step.dependOn(&run_freebsd_boot_tests.step);
        aggregate_test_step.dependOn(&run_release_support_tests.step);
        aggregate_test_step.dependOn(&run_azure_vhd_tests.step);
        aggregate_test_step.dependOn(&run_python_inventory_tests.step);
        aggregate_test_step.dependOn(&run_nbd_mod_tests.step);
        aggregate_test_step.dependOn(&run_nbd_exe_tests.step);
        aggregate_test_step.dependOn(&run_nbd_server_tests.step);
        aggregate_test_step.dependOn(&run_qcow2_mod_tests.step);
        aggregate_test_step.dependOn(&run_qcow2_exe_tests.step);
        aggregate_test_step.dependOn(&run_mizinit_tests.step);
        aggregate_test_step.dependOn(&run_mizguest_tests.step);
        aggregate_test_step.dependOn(mizguest_step);
        aggregate_test_step.dependOn(&run_stale_brand_tests.step);
        aggregate_test_step.dependOn(&run_build_api_tests.step);
        aggregate_test_step.dependOn(&build_api_consumer_check.step);
        aggregate_test_step.dependOn(&package_family_consumer_check.step);
        aggregate_test_step.dependOn(&build_api_diagnostics_check.step);
        aggregate_test_step.dependOn(
            &build_api_execution_diagnostics_check.step,
        );
        aggregate_test_step.dependOn(
            &build_api_preserved_diagnostics_check.step,
        );
        aggregate_test_step.dependOn(
            &build_api_preserved_vm_diagnostics_check.step,
        );
    }
    test_step.dependOn(&run_device_write_integration.step);
    test_step.dependOn(&run_unsafe_chroot_integration.step);
    test_step.dependOn(&run_vm_backend_integration.step);
}
