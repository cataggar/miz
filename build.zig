const std = @import("std");

const image_build = @import("build/image.zig");
const oci_build = @import("build/oci.zig");

const AzureLinuxArchitecture = enum {
    x86_64,
    aarch64,
};

const AzureLinuxFlavor = enum {
    core,
    full,
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

test {
    std.testing.refAllDecls(oci_build);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const azurelinux_architecture = b.option(
        AzureLinuxArchitecture,
        "azurelinux-arch",
        "Azure Linux guest architecture: x86_64 (default) or aarch64",
    ) orelse .x86_64;
    const azurelinux_flavor = b.option(
        AzureLinuxFlavor,
        "azurelinux-flavor",
        "Azure Linux guest flavor: core (default, zvminit) or full (official vm-base/systemd)",
    ) orelse .core;
    const bzip2 = b.dependency("bzip2", .{
        .target = target,
        .optimize = optimize,
        .linkage = .static,
        .bz2 = true,
        .bzip2 = false,
        .bzip2recover = false,
    });
    const host_bzip2 = b.dependency("bzip2", .{
        .target = b.graph.host,
        .optimize = optimize,
        .linkage = .static,
        .bz2 = true,
        .bzip2 = false,
        .bzip2recover = false,
    });

    // ---- packages/zvmi: the core disk-image library ----
    const zvmi_mod = b.addModule("zvmi", .{
        .root_source_file = b.path("packages/zvmi/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const host_zvmi_mod = b.createModule(.{
        .root_source_file = b.path("packages/zvmi/src/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });

    const zvmi_tests = b.addTest(.{ .root_module = zvmi_mod });
    const run_zvmi_tests = b.addRunArtifact(zvmi_tests);
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
                .{ .name = "zvmi", .module = host_zvmi_mod },
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
        .link_libc = true,
    });
    qemu_host_mod.linkLibrary(bzip2.artifact("bz2"));
    const guest_validation_mod = b.addModule("guest_validation", .{
        .root_source_file = b.path("azagent/validation.zig"),
        .target = target,
        .optimize = optimize,
    });
    const qemu_host_tests = b.addTest(.{ .root_module = qemu_host_mod });
    const run_qemu_host_tests = b.addRunArtifact(qemu_host_tests);

    // ---- azagent: minimal guest provisioning agent for first-boot Azure
    // VM setup (issue #112). Statically linked for self-containment
    // (matching zvminit's philosophy), but -- unlike zvminit, which is
    // pinned to a single real-boot x86_64 QEMU test fixture -- built for
    // the standard target/optimize so it supports every Linux architecture
    // a given image targets (Azure supports Arm64 VMs too) and remains
    // natively testable via `zig build test` on any host.
    // Imports `zvmi` too (issue #113's resource-disk setup reuses
    // `mbr.zig`/`ext4.zig` directly against a real block device). ----
    const azagent_mod = b.createModule(.{
        .root_source_file = b.path("azagent/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wireserver", .module = wireserver_mod },
            .{ .name = "zvmi", .module = zvmi_mod },
        },
    });

    if (target.result.os.tag == .linux) {
        const azagent_exe = b.addExecutable(.{
            .name = "azagent",
            .root_module = azagent_mod,
            .linkage = .static,
        });
        b.installArtifact(azagent_exe);
    }

    const azagent_tests = b.addTest(.{ .root_module = azagent_mod });
    const run_azagent_tests = b.addRunArtifact(azagent_tests);
    const azagent_test_step = b.step("test-azagent", "Run azagent tests");
    azagent_test_step.dependOn(&run_azagent_tests.step);

    // ---- cli: the `zvmi` executable ----
    const cli_exe = b.addExecutable(.{
        .name = "zvmi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = zvmi_mod },
                .{ .name = "qemu_host", .module = qemu_host_mod },
                .{ .name = "guest_validation", .module = guest_validation_mod },
            },
        }),
    });
    const install_cli = b.addInstallArtifact(cli_exe, .{});
    b.getInstallStep().dependOn(&install_cli.step);

    const install_cli_step = b.step("install-zvmi", "Install only the zvmi CLI");
    install_cli_step.dependOn(&install_cli.step);

    const run_cmd = b.addRunArtifact(cli_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zvmi");
    run_step.dependOn(&run_cmd.step);

    const cli_tests = b.addTest(.{ .root_module = cli_exe.root_module });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    const cli_test_step = b.step("test-cli", "Run zvmi CLI tests");
    cli_test_step.dependOn(&run_cli_tests.step);

    // Host-only image builders used by the exported build helpers. They remain
    // executable even when the dependency is configured for a foreign target.
    const image_builder_exe = b.addExecutable(.{
        .name = "zvmi-image-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/image_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = host_zvmi_mod },
            },
        }),
    });
    b.installArtifact(image_builder_exe);

    const preserved_image_wire_mod = b.createModule(.{
        .root_source_file = b.path("packages/zvmi/src/preserved_image_wire.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const preserved_image_builder_exe = b.addExecutable(.{
        .name = "zvmi-preserved-image-builder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/src/preserved_image_builder.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = host_zvmi_mod },
            },
        }),
    });
    b.installArtifact(preserved_image_builder_exe);
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
        .name = "zvmi-input-validator",
        .root_module = input_validator_mod,
    });
    b.installArtifact(input_validator_exe);
    const input_validator_tests = b.addTest(.{ .root_module = input_validator_mod });
    const run_input_validator_tests = b.addRunArtifact(input_validator_tests);

    const image_status_check_mod = b.createModule(.{
        .root_source_file = b.path("cli/src/image_status_check.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const image_status_check_exe = b.addExecutable(.{
        .name = "zvmi-image-status-check",
        .root_module = image_status_check_mod,
    });
    b.installArtifact(image_status_check_exe);
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
    // driving zvmi.build_image.build() output with qmp. Lives outside
    // packages/zvmi since it needs both zvmi and qmp -- see issue #99. ----
    const boot_smoke_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/boot_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zvmi", .module = zvmi_mod },
            .{ .name = "qmp", .module = qmp_mod },
            .{ .name = "qemu_host", .module = qemu_host_mod },
        },
    }) });
    const run_boot_smoke_tests = b.addRunArtifact(boot_smoke_tests);
    const boot_smoke_step = b.step("test-boot-smoke", "Run opportunistic real-QEMU boot-smoke tests");
    boot_smoke_step.dependOn(&run_boot_smoke_tests.step);

    const unsafe_chroot_integration_exe = b.addExecutable(.{
        .name = "zvmi-unsafe-chroot-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unsafe_chroot_integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = host_zvmi_mod },
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

    const host_qmp_mod = b.createModule(.{
        .root_source_file = b.path("qmp/src/qmp.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const host_qemu_host_mod = b.createModule(.{
        .root_source_file = b.path("qemu/host.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .link_libc = true,
    });
    host_qemu_host_mod.linkLibrary(host_bzip2.artifact("bz2"));
    const freebsd_boot_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/freebsd15_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "qmp", .module = host_qmp_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
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
    const unsafe_chroot_real_boot_exe = b.addExecutable(.{
        .name = "zvmi-unsafe-chroot-real-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unsafe_chroot_real_boot.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = host_zvmi_mod },
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

    const qcow2_mod_tests = b.addTest(.{ .root_module = qcow2_mod });
    const run_qcow2_mod_tests = b.addRunArtifact(qcow2_mod_tests);
    const qcow2_exe_tests = b.addTest(.{ .root_module = qcow2_exe.root_module });
    const run_qcow2_exe_tests = b.addRunArtifact(qcow2_exe_tests);

    // ---- zvminit: standalone minimal PID 1 for generalized Azure Linux
    // core images. Its guest target follows -Dazurelinux-arch, while the
    // ordinary CLI, builder, and preload library remain host-native. ----
    const zvminit_target = b.resolveTargetQuery(.{
        .cpu_arch = switch (azurelinux_architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .os_tag = .linux,
    });
    const zvminit_cdrom_mod = b.createModule(.{
        .root_source_file = b.path("azagent/cdrom.zig"),
        .target = zvminit_target,
        .optimize = .ReleaseSmall,
    });
    const zvminit_mod = b.createModule(.{
        .root_source_file = b.path("zvminit/init.zig"),
        .target = zvminit_target,
        .optimize = .ReleaseSmall,
        .imports = &.{
            .{ .name = "provisioning_media", .module = zvminit_cdrom_mod },
        },
    });
    const zvminit_exe = b.addExecutable(.{
        .name = "zvminit",
        .root_module = zvminit_mod,
        .linkage = .static,
    });
    b.installArtifact(zvminit_exe);

    const zvminit_test_cdrom_mod = b.createModule(.{
        .root_source_file = b.path("azagent/cdrom.zig"),
        .target = target,
        .optimize = optimize,
    });
    const zvminit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("zvminit/init.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "provisioning_media", .module = zvminit_test_cdrom_mod },
            },
        }),
    });
    const run_zvminit_tests = b.addRunArtifact(zvminit_tests);
    const zvminit_test_step = b.step("test-zvminit", "Run zvminit tests");
    zvminit_test_step.dependOn(&run_zvminit_tests.step);

    // ---- zvmiguest: the static, libc-free PID 1 that the vm customization
    // backend appends to the target image's own initramfs. It is built for
    // every architecture the backend can drive a guest at, not just the host's,
    // because cross-architecture customization is the point. ----
    const guest_architectures = [_]std.Target.Cpu.Arch{ .x86_64, .aarch64 };
    const zvmiguest_step = b.step(
        "zvmiguest",
        "Build the in-VM guest agent for every supported guest architecture",
    );
    for (guest_architectures) |architecture| {
        const guest_target = b.resolveTargetQuery(.{
            .cpu_arch = architecture,
            .os_tag = .linux,
        });
        const guest_control_mod = b.createModule(.{
            .root_source_file = b.path("packages/zvmi/src/vm_control.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
        });
        const zvmiguest_exe = b.addExecutable(.{
            .name = b.fmt("zvmi-guest-agent-{s}", .{@tagName(architecture)}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("zvmiguest/main.zig"),
                .target = guest_target,
                .optimize = .ReleaseSmall,
                .imports = &.{
                    .{ .name = "vm_control", .module = guest_control_mod },
                },
            }),
            .linkage = .static,
        });
        b.installArtifact(zvmiguest_exe);
        zvmiguest_step.dependOn(&zvmiguest_exe.step);
    }

    const zvmiguest_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("zvmiguest/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vm_control", .module = b.createModule(.{
                    .root_source_file = b.path("packages/zvmi/src/vm_control.zig"),
                    .target = target,
                    .optimize = optimize,
                }) },
            },
        }),
    });
    const run_zvmiguest_tests = b.addRunArtifact(zvmiguest_tests);
    const zvmiguest_test_step = b.step("test-zvmiguest", "Run guest agent tests");
    zvmiguest_test_step.dependOn(&run_zvmiguest_tests.step);

    const test_step = b.step("test", "Run all tests");

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
        "--help",
    });
    build_api_consumer_check.setName("check external build.zig consumer");
    build_api_consumer_check.setCwd(b.path("tests/build_api_consumer"));

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

        // Guest-targeted azagent for embedding in the generalized image.
        // It follows -Dazurelinux-arch and is static/ReleaseSmall, matching
        // zvminit.
        const zvmi_guest_mod = b.createModule(.{
            .root_source_file = b.path("packages/zvmi/src/root.zig"),
            .target = zvminit_target,
            .optimize = .ReleaseSmall,
        });
        const wireserver_guest_mod = b.createModule(.{
            .root_source_file = b.path("wireserver/wireserver.zig"),
            .target = zvminit_target,
            .optimize = .ReleaseSmall,
        });
        const azagent_guest_mod = b.createModule(.{
            .root_source_file = b.path("azagent/main.zig"),
            .target = zvminit_target,
            .optimize = .ReleaseSmall,
            .imports = &.{
                .{ .name = "wireserver", .module = wireserver_guest_mod },
                .{ .name = "zvmi", .module = zvmi_guest_mod },
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
                .{ .name = "zvmi", .module = host_zvmi_mod },
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
            generalized_check_step.dependOn(&zvminit_exe.step);
            generalized_check_step.dependOn(&azagent_guest_exe.step);
        }
        generalized_check_step.dependOn(&zstd_preload_lib.step);

        // `zig build generalized-azurelinux4 -- [--iso ...] [--output ...] ...`
        // Automatically passes the paths of the just-built native zvmi, guest
        // zvminit/azagent, and the preload library so the builder does not need to
        // invoke `zig build` itself.
        const run_builder = b.addRunArtifact(builder_exe);
        run_builder.step.dependOn(b.getInstallStep());
        run_builder.addArg("--architecture");
        run_builder.addArg(@tagName(azurelinux_architecture));
        run_builder.addArg("--flavor");
        run_builder.addArg(@tagName(azurelinux_flavor));
        run_builder.addArg("--zvmi");
        run_builder.addArtifactArg(cli_exe);
        if (azurelinux_flavor == .core) {
            run_builder.addArg("--zvminit");
            run_builder.addArtifactArg(zvminit_exe);
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
        test_step.dependOn(&run_builder_tests.step);
        test_step.dependOn(generalized_check_step);

        // Opt-in native-QEMU acceptance for a completed, finalized release
        // candidate. The image itself is intentionally supplied at runtime:
        // four native matrix entries select their architecture/flavor here and
        // set ZVMI_AZURELINUX4_IMAGE to the exact candidate under test.
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
                    .{ .name = "zvmi", .module = host_zvmi_mod },
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

        const freebsd_builder_mod = b.createModule(.{
            .root_source_file = b.path("scripts/build_generalized_freebsd15.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zvmi", .module = host_zvmi_mod },
                .{ .name = "qmp", .module = host_qmp_mod },
                .{ .name = "qemu_host", .module = host_qemu_host_mod },
            },
        });
        const freebsd_builder_exe = b.addExecutable(.{
            .name = "build_generalized_freebsd15",
            .root_module = freebsd_builder_mod,
        });
        b.installArtifact(freebsd_builder_exe);

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
        test_step.dependOn(&run_freebsd_builder_tests.step);
    }

    test_step.dependOn(&run_zvmi_tests.step);
    test_step.dependOn(&run_oci_registry_tests.step);
    test_step.dependOn(&run_wireserver_tests.step);
    test_step.dependOn(&run_qemu_host_tests.step);
    test_step.dependOn(&run_azagent_tests.step);
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_preserved_image_builder_tests.step);
    test_step.dependOn(&run_preserved_image_wire_tests.step);
    test_step.dependOn(&run_input_validator_tests.step);
    test_step.dependOn(&run_image_status_check_tests.step);
    test_step.dependOn(&run_qmp_mod_tests.step);
    test_step.dependOn(&run_qmp_exe_tests.step);
    test_step.dependOn(&run_qmp_codegen_tests.step);
    test_step.dependOn(&run_qmp_schema_tests.step);
    test_step.dependOn(&run_boot_smoke_tests.step);
    test_step.dependOn(&run_freebsd_boot_tests.step);
    test_step.dependOn(&run_unsafe_chroot_integration.step);
    test_step.dependOn(&run_nbd_mod_tests.step);
    test_step.dependOn(&run_nbd_exe_tests.step);
    test_step.dependOn(&run_nbd_server_tests.step);
    test_step.dependOn(&run_qcow2_mod_tests.step);
    test_step.dependOn(&run_qcow2_exe_tests.step);
    test_step.dependOn(&run_zvminit_tests.step);
    test_step.dependOn(&run_zvmiguest_tests.step);
    test_step.dependOn(zvmiguest_step);
    test_step.dependOn(&run_build_api_tests.step);
    test_step.dependOn(&build_api_consumer_check.step);
    test_step.dependOn(&build_api_diagnostics_check.step);
    test_step.dependOn(&build_api_execution_diagnostics_check.step);
    test_step.dependOn(&build_api_preserved_diagnostics_check.step);
    test_step.dependOn(&build_api_preserved_vm_diagnostics_check.step);
}
