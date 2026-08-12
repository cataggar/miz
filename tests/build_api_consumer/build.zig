const std = @import("std");
const zvmi = @import("zvmi");

pub fn build(b: *std.Build) void {
    const dependency = b.dependencyFromBuildZig(zvmi, .{
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });

    const pull = zvmi.addOciPull(b, dependency, .{
        .name = "remote-container",
        .source = "docker://registry.example/team/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .platform = .{ .os = "linux", .architecture = "amd64" },
    });
    _ = zvmi.addImage(b, dependency, .{
        .name = "remote-layout-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .oci_layout = pull.layout },
        },
        .output = .{
            .format = .qcow2,
            .basename = "remote-layout-fixture.qcow2",
        },
        .size = 256 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x55} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
    });

    // A registry image named by the request itself, rather than pulled beside
    // it by addOciPull.  Only configured, never built: the point is that the
    // exported API accepts it and emits the flags.
    _ = zvmi.addImage(b, dependency, .{
        .name = "registry-image-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .registry = .{
                .reference = "docker://registry.example/team/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                .username = "builder",
                .password_file = b.path("fixtures/registry-password"),
                .tls_ca = b.path("fixtures/registry-ca.pem"),
            } },
        },
        .output = .{
            .format = .qcow2,
            .basename = "registry-image-fixture.qcow2",
        },
        .size = 256 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x77} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
    });

    const layout_image = zvmi.addImage(b, dependency, .{
        .name = "layout-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .oci_layout = b.path("fixtures/oci-layout") },
        },
        .output = .{
            .format = .qcow2,
            .basename = "layout-fixture.qcow2",
        },
        .size = 256 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x11} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
        .os = .{
            .filesystem = &.{
                .{ .put_file = .{
                    .path = "/etc/inline.conf",
                    .source = .{ .inline_bytes = "source=inline\n" },
                } },
                .{ .put_file = .{
                    .path = "/etc/tracked.conf",
                    .source = .{ .path = b.path("fixtures/custom.conf") },
                    .metadata = .{ .mode = 0o640 },
                } },
                .{ .put_symlink = .{
                    .path = "/tracked.conf",
                    .target = "etc/tracked.conf",
                } },
            },
            .hostname = "build-api-vm",
            .services = &.{.{ .name = "example.service", .state = .enabled }},
            .kernel_modules = &.{.{ .name = "hv_netvsc", .load = true }},
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
    });

    const archive_image = zvmi.addImage(b, dependency, .{
        .name = "archive-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .archive = b.path("fixtures/container.tar") },
        },
        .output = .{
            .format = .vhd,
            .basename = "archive-fixture.vhd",
        },
        .size = 64 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x22} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
        .boot_mode = .both,
        .uki = .{
            .stub_source_path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub",
            .os_release_source_path = "usr/lib/os-release",
            .splash_source_path = "usr/share/plymouth/splash.bmp",
            .output_directory = "EFI/Custom",
        },
    });

    // A LiveOS ISO product, configured through the exported `addIso` helper.
    // Only configured, never built here: this verifies the ISO build API wires
    // and typechecks in an external consumer, alongside the disk-image helpers.
    _ = zvmi.addIso(b, dependency, .{
        .name = "liveos-fixture",
        .iso = b.path("fixtures/os.iso"),
        .container = .{ .oci_layout = pull.layout },
        .rootfs_size = 256 * 1024 * 1024,
        .output_basename = "liveos-fixture.iso",
        .rootfs_path_in_iso = "LiveOS/squashfs.img",
        .boot_images = &.{
            .{ .platform = .uefi, .image_path = "boot/grub2/efiboot.img" },
            .{ .platform = .bios, .image_path = "boot/grub2/i386-pc/eltorito.img" },
        },
        .squashfs_compression = .zstd,
        .source_date_epoch = 1_735_689_600,
        .os = .{
            .hostname = "liveos",
            .users = &.{.{ .name = "admin", .password = .locked }},
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
    });

    _ = zvmi.addImage(b, dependency, .{
        .name = "cosi-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .oci_layout = b.path("fixtures/oci-layout") },
        },
        .output = .{
            .format = .cosi,
            .basename = "cosi-fixture.cosi",
        },
        .size = 256 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x44} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
    });

    const execution_failure_image = zvmi.addImage(b, dependency, .{
        .name = "execution-failure-fixture",
        .input = .{
            .iso = b.path("fixtures/os.iso"),
            .container = .{ .archive = b.path("fixtures/container.tar") },
        },
        .output = .{
            .format = .qcow2,
            .basename = "execution-failure-fixture.qcow2",
        },
        .size = 256 * 1024 * 1024,
        .target_architecture = .x86_64,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x33} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
    });

    const foreign_dependency = b.dependencyFromBuildZig(zvmi, .{
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
        }),
        .optimize = .ReleaseSafe,
    });
    const preserved_image = zvmi.addPreservedImage(b, foreign_dependency, .{
        .name = "preserved-fixture",
        .input = .{
            .disk = b.path("fixtures/os.iso"),
            .dependencies = &.{b.path("fixtures/container.tar")},
        },
        .root_partition = .{ .gpt_index = 2 },
        .output = .{
            .format = .qcow2,
            .basename = "preserved-fixture.qcow2",
        },
        .target_architecture = .aarch64,
        .backend = .unsafe_chroot,
        .acknowledge_unsafe = true,
        .reproducibility = .{
            .seed = [_]u8{0x44} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
        .operations = &.{
            .{ .overwrite_file = .{
                .path = "/etc/inline.conf",
                .source = .{ .inline_bytes = "source=preserved-inline\n" },
            } },
            .{ .remove_file = "/etc/obsolete.conf" },
            .{ .overwrite_file = .{
                .path = "/etc/tracked.conf",
                .source = .{ .path = b.path("fixtures/custom.conf") },
            } },
            .{ .remove_tree = "/var/cache/obsolete" },
        },
        .os = .{
            .filesystem = &.{
                .{ .put_file = .{
                    .path = "/etc/rebuilt.conf",
                    .source = .{ .inline_bytes = "source=rebuild\n" },
                } },
                .{ .put_directory = .{ .path = "/opt/rebuilt" } },
            },
            .hostname = "rebuilt",
        },
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &.{.{
                .id = "base",
                .urls = &.{"https://packages.example.invalid"},
                .trust = &.{.{ .inline_bytes = "test signing key" }},
            }},
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.12.0-test"},
        } },
        .guest_execution = .same_architecture,
    });

    // The vm backend on a foreign guest architecture, so the external consumer
    // path covers cross-architecture execution and the VM policy end to end.
    const preserved_vm_image = zvmi.addPreservedImage(b, foreign_dependency, .{
        .name = "preserved-vm-fixture",
        .input = .{ .disk = b.path("fixtures/os.iso") },
        .root_partition = .{ .gpt_index = 2 },
        .output = .{
            .format = .qcow2,
            .basename = "preserved-vm-fixture.qcow2",
        },
        .target_architecture = .aarch64,
        .backend = .vm,
        .reproducibility = .{
            .seed = [_]u8{0x55} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
        .guest_execution = .cross_architecture,
        .runner = .{
            .kind = .vm,
            .guest_architecture = .aarch64,
            .command = "/usr/bin/qemu-system-aarch64",
        },
        .vm = .{
            .emulator_command = "/usr/bin/qemu-system-aarch64",
            .acceleration = .software,
            // Set so the fixture resolves identically whether or not the
            // builder host happens to be aarch64.
            .acknowledge_software_emulation = true,
        },
    });

    const install_layout = b.addInstallFile(layout_image.path, "images/layout-fixture.qcow2");
    const install_archive = b.addInstallFile(archive_image.path, "images/archive-fixture.vhd");
    const install_plan = b.addInstallFile(layout_image.plan_path, "images/layout-fixture.plan.json");
    const install_provenance = b.addInstallFile(layout_image.provenance_path, "images/layout-fixture.provenance.json");
    const image_step = b.step("image", "Build and install both fixture images");
    image_step.dependOn(&install_layout.step);
    image_step.dependOn(&install_archive.step);
    image_step.dependOn(&install_plan.step);
    image_step.dependOn(&install_provenance.step);

    const install_diagnostics = b.addInstallFile(layout_image.preflight_diagnostics_path, "images/layout-fixture.diagnostics.json");
    const install_failure_plan = b.addInstallFile(layout_image.preflight_plan_path, "images/layout-fixture.failure-plan.json");
    const install_failure_provenance = b.addInstallFile(layout_image.preflight_provenance_path, "images/layout-fixture.failure-provenance.json");
    const diagnostics_step = b.step("diagnostics", "Produce diagnostics without requiring a successful image");
    diagnostics_step.dependOn(&install_diagnostics.step);
    diagnostics_step.dependOn(&install_failure_plan.step);
    diagnostics_step.dependOn(&install_failure_provenance.step);

    const install_execution_diagnostics = b.addInstallFile(
        execution_failure_image.diagnostics_path,
        "images/execution-failure-fixture.diagnostics.json",
    );
    const execution_diagnostics_step = b.step("execution-diagnostics", "Produce structured diagnostics for a retryable execution failure");
    execution_diagnostics_step.dependOn(&install_execution_diagnostics.step);

    const install_preserved_diagnostics = b.addInstallFile(
        preserved_image.preflight_diagnostics_path,
        "images/preserved-fixture.diagnostics.json",
    );
    const preserved_diagnostics_step = b.step(
        "preserved-diagnostics",
        "Exercise preserved-image preflight with a foreign dependency target",
    );
    preserved_diagnostics_step.dependOn(&install_preserved_diagnostics.step);

    const install_preserved_vm_diagnostics = b.addInstallFile(
        preserved_vm_image.preflight_diagnostics_path,
        "images/preserved-vm-fixture.diagnostics.json",
    );
    const preserved_vm_diagnostics_step = b.step(
        "preserved-vm-diagnostics",
        "Exercise the vm backend and a cross-architecture runner through preflight",
    );
    preserved_vm_diagnostics_step.dependOn(&install_preserved_vm_diagnostics.step);
}
