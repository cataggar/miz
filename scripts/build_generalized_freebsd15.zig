//! Build a generalized FreeBSD 15.1 QCOW2 from an official architecture-
//! matched
//! BASIC-CLOUDINIT image. The source is verified and decompressed before a
//! nonce-authenticated NoCloud customization runs under UEFI QEMU.

const std = @import("std");
const builtin = @import("builtin");
const zvmi = @import("zvmi");
const qmp = @import("qmp");
const qemu_host = @import("qemu_host");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const artifact_pipeline = zvmi.artifact_pipeline;

const source_max_size: u64 = 2 * 1024 * 1024 * 1024;
const image_max_size: u64 = 6 * 1024 * 1024 * 1024;
const finalized_image_max_size: u64 = 7 * 1024 * 1024 * 1024;
const xz_memory_limit: u64 = 1024 * 1024 * 1024;
const seed_iso_max_size: u64 = 4 * 1024 * 1024;
const firmware_max_size: u64 = 128 * 1024 * 1024;
const default_customization_timeout_seconds: u32 = 30 * 60;
const qmp_connect_timeout_seconds: u32 = 10;
const customization_result_prefix = "ZVMI_FREEBSD_CUSTOMIZATION_RESULT";
const serial_tail_size: usize = 256 * 1024;

/// Root filesystem of the upstream BASIC-CLOUDINIT image and therefore of the
/// published artifact. FreeBSD's UFS and ZFS VM images do not share a disk
/// layout: the UFS image names its root in `/etc/fstab` and grows with
/// `growfs(8)`, while the ZFS image has no root fstab entry and grows by
/// onlining the expanded pool vdev. Selecting between them must always be an
/// explicit profile decision rather than an assumption made by shared code.
const RootFilesystem = enum {
    ufs,
    zfs,

    fn parse(text: []const u8) ?RootFilesystem {
        if (std.mem.eql(u8, text, "ufs")) return .ufs;
        if (std.mem.eql(u8, text, "zfs")) return .zfs;
        return null;
    }
};

/// Content flavor of the published artifact. Only the full generalized image
/// exists today; a `core` flavor that trims the package set reuses this same
/// profile table instead of introducing a parallel one.
const Flavor = enum {
    full,

    fn parse(text: []const u8) ?Flavor {
        if (std.mem.eql(u8, text, "full")) return .full;
        return null;
    }
};

/// Filesystem-specific root growth and swap handling. The payloads carry the
/// facts each path needs and nothing the other path could misread: the UFS
/// arm knows the fstab root line that must survive swap removal, and the ZFS
/// arm knows the root pool whose vdev is grown and whose GUID is reset.
const RootStorage = union(RootFilesystem) {
    ufs: struct {
        /// Extended regular expression that the post-generalization
        /// `/etc/fstab` must still match. Dropping the UFS root line while
        /// stripping swap would produce an unbootable image.
        fstab_root_pattern: []const u8,
    },
    zfs: struct {
        /// Pool that carries `/`. Growth onlines this pool's vdev and
        /// `zpool_reguid` re-randomizes its GUID on every first boot.
        pool: []const u8,
    },

    fn filesystem(self: RootStorage) RootFilesystem {
        return self;
    }
};

const Profile = struct {
    architecture: Architecture,
    flavor: Flavor,
    root_storage: RootStorage,
    source_name: []const u8,
    source_url: []const u8,
    source_sha256: []const u8,
    virtual_size: u64,
    output: []const u8,
    work_dir: []const u8,

    fn rootFilesystem(self: *const Profile) RootFilesystem {
        return self.root_storage.filesystem();
    }
};

const ufs_root_storage = RootStorage{
    .ufs = .{
        // FreeBSD labels the UFS root partition `rootfs` and mounts it through
        // /dev/gpt/rootfs, so the surviving fstab line is stable across
        // architectures.
        .fstab_root_pattern = "^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]",
    },
};

// release/tools/vmimage.subr creates the ZFS VM images with -o poolname=zroot
// and bootfs=zroot/ROOT/default on both release architectures.
const zfs_root_storage = RootStorage{ .zfs = .{ .pool = "zroot" } };

/// Every architecture x filesystem x flavor combination this builder can
/// produce. Keeping the pinned source metadata, virtual size, and output
/// naming in one table makes an unsupported combination a lookup failure
/// rather than a half-applied set of defaults.
const profiles = [_]Profile{
    .{
        .architecture = .aarch64,
        .flavor = .full,
        .root_storage = ufs_root_storage,
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_url = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/aarch64/Latest/FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963",
        .virtual_size = 6_477_643_776,
        .output = "FreeBSD-15.1-aarch64.qcow2",
        .work_dir = ".scratch/generalized-freebsd15-aarch64",
    },
    .{
        .architecture = .x86_64,
        .flavor = .full,
        .root_storage = ufs_root_storage,
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_url = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/amd64/Latest/FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f",
        .virtual_size = 6_477_709_312,
        .output = "FreeBSD-15.1-x86_64.qcow2",
        .work_dir = ".scratch/generalized-freebsd15-x86_64",
    },
    .{
        .architecture = .aarch64,
        .flavor = .full,
        .root_storage = zfs_root_storage,
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_url = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/aarch64/Latest/FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "0911a033b0a5d060486f92e534f3482c6a2ab96af6abb8a60683eeb24f6746af",
        .virtual_size = 6_477_643_776,
        .output = "FreeBSD-15.1-aarch64.zfs.qcow2",
        .work_dir = ".scratch/generalized-freebsd15-aarch64-zfs",
    },
    .{
        .architecture = .x86_64,
        .flavor = .full,
        .root_storage = zfs_root_storage,
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_url = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/amd64/Latest/FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "4159e137d4a78f46b62d3523edd9a4dc79fd0cdcf17e34e531342f52333f4131",
        .virtual_size = 6_477_840_384,
        .output = "FreeBSD-15.1-x86_64.zfs.qcow2",
        .work_dir = ".scratch/generalized-freebsd15-x86_64-zfs",
    },
};

fn findProfile(
    architecture: Architecture,
    root_filesystem: RootFilesystem,
    flavor: Flavor,
) ?*const Profile {
    for (&profiles) |*profile| {
        if (profile.architecture == architecture and
            profile.rootFilesystem() == root_filesystem and
            profile.flavor == flavor)
        {
            return profile;
        }
    }
    return null;
}

const Architecture = enum {
    aarch64,
    x86_64,

    fn parse(text: []const u8) ?Architecture {
        if (std.mem.eql(u8, text, "aarch64")) return .aarch64;
        if (std.mem.eql(u8, text, "x86_64")) return .x86_64;
        return null;
    }

    fn guestArchitecture(self: Architecture) qemu_host.GuestArchitecture {
        return switch (self) {
            .aarch64 => .aarch64,
            .x86_64 => .x86_64,
        };
    }

    fn hostCpu(self: Architecture) std.Target.Cpu.Arch {
        return switch (self) {
            .aarch64 => .aarch64,
            .x86_64 => .x86_64,
        };
    }

    fn qemuName(self: Architecture) []const u8 {
        return qemu_host.qemuSystemName(self.guestArchitecture());
    }

    fn machineArg(self: Architecture, accel: Accel) []const u8 {
        return switch (self) {
            .aarch64 => switch (accel) {
                .kvm => "virt,accel=kvm",
                .tcg => "virt,accel=tcg",
                .auto => unreachable,
            },
            .x86_64 => switch (accel) {
                .kvm => "q35,accel=kvm",
                .tcg => "q35,accel=tcg",
                .auto => unreachable,
            },
        };
    }

    fn cpuArg(self: Architecture, accel: Accel) []const u8 {
        if (accel == .kvm) return "host";
        return switch (self) {
            .aarch64 => "max",
            .x86_64 => "qemu64",
        };
    }
};

const Accel = enum {
    auto,
    kvm,
    tcg,

    fn parse(text: []const u8) ?Accel {
        if (std.mem.eql(u8, text, "auto")) return .auto;
        if (std.mem.eql(u8, text, "kvm")) return .kvm;
        if (std.mem.eql(u8, text, "tcg")) return .tcg;
        return null;
    }
};

const Args = struct {
    architecture: Architecture = .aarch64,
    root_filesystem: RootFilesystem = .ufs,
    flavor: Flavor = .full,
    profile: *const Profile = undefined,
    source: ?[]const u8 = null,
    source_sha256: []const u8 = "",
    output: []const u8 = "",
    work_dir: []const u8 = "",
    curl_path: []const u8 = "curl",
    xz_path: []const u8 = "xz",
    qemu_img_path: []const u8 = "qemu-img",
    qemu_path: []const u8 = "",
    xorriso_path: []const u8 = "xorriso",
    uefi_code_path: ?[]const u8 = null,
    uefi_vars_path: ?[]const u8 = null,
    accel: Accel = .auto,
    customization_timeout_seconds: u32 = default_customization_timeout_seconds,
    base_only: bool = false,
};

const help_text =
    \\Usage: build_generalized_freebsd15 [options]
    \\
    \\  --architecture <arch>    Guest architecture: aarch64 (default) or x86_64
    \\  --filesystem <fs>        Root filesystem: ufs (default) or zfs
    \\  --flavor <flavor>        Image flavor: full (default)
    \\  --source <path>          Local .qcow2.xz source (official image if omitted)
    \\  --source-sha256 <hex>    Expected compressed source SHA-256
    \\  --output <path>          Output QCOW2
    \\  --work-dir <dir>         Download/decompression cache directory
    \\  --curl <path>            curl executable (default: curl)
    \\  --xz <path>              XZ Utils executable (default: xz)
    \\  --qemu-img <path>        qemu-img executable (default: qemu-img)
    \\  --qemu <path>            Architecture-matched qemu-system executable
    \\  --xorriso <path>         xorriso executable used for the NoCloud ISO
    \\  --uefi-code <path>       Architecture-matched UEFI pflash code image
    \\  --uefi-vars <path>       Architecture-matched UEFI pflash variables template
    \\  --accel <auto|kvm|tcg>   QEMU accelerator (default: auto)
    \\  --timeout <seconds>      Guest customization timeout (default: 1800)
    \\  --base-only              Prepare the verified upstream base without customization
    \\
    \\Preferred invocation: zig build generalized-freebsd15 -- [options]
    \\
;

fn parseArgs(argv: []const []const u8) !Args {
    var args = Args{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--architecture")) {
            args.architecture = Architecture.parse(try nextValue(argv, &i)) orelse
                return error.InvalidArchitecture;
        } else if (std.mem.eql(u8, arg, "--filesystem")) {
            args.root_filesystem = RootFilesystem.parse(try nextValue(argv, &i)) orelse
                return error.InvalidRootFilesystem;
        } else if (std.mem.eql(u8, arg, "--flavor")) {
            args.flavor = Flavor.parse(try nextValue(argv, &i)) orelse
                return error.InvalidFlavor;
        } else if (std.mem.eql(u8, arg, "--source")) {
            args.source = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--source-sha256")) {
            args.source_sha256 = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--output")) {
            args.output = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--work-dir")) {
            args.work_dir = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--curl")) {
            args.curl_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--xz")) {
            args.xz_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--qemu-img")) {
            args.qemu_img_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--qemu")) {
            args.qemu_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--xorriso")) {
            args.xorriso_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--uefi-code")) {
            args.uefi_code_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--uefi-vars")) {
            args.uefi_vars_path = try nextValue(argv, &i);
        } else if (std.mem.eql(u8, arg, "--accel")) {
            args.accel = Accel.parse(try nextValue(argv, &i)) orelse
                return error.InvalidAccelerator;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            args.customization_timeout_seconds = std.fmt.parseUnsigned(
                u32,
                try nextValue(argv, &i),
                10,
            ) catch return error.InvalidTimeout;
            if (args.customization_timeout_seconds == 0) {
                return error.InvalidTimeout;
            }
        } else if (std.mem.eql(u8, arg, "--base-only")) {
            args.base_only = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            std.debug.print("{s}", .{help_text});
            std.process.exit(0);
        } else {
            return error.UnexpectedArgument;
        }
    }
    if ((args.uefi_code_path == null) != (args.uefi_vars_path == null)) {
        return error.IncompleteFirmwareOverride;
    }
    const profile = findProfile(
        args.architecture,
        args.root_filesystem,
        args.flavor,
    ) orelse return error.UnsupportedProfile;
    args.profile = profile;
    if (args.source_sha256.len == 0) args.source_sha256 = profile.source_sha256;
    if (args.output.len == 0) args.output = profile.output;
    if (args.work_dir.len == 0) args.work_dir = profile.work_dir;
    if (args.qemu_path.len == 0) args.qemu_path = args.architecture.qemuName();
    return args;
}

fn nextValue(argv: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= argv.len) return error.MissingValue;
    return argv[index.*];
}

fn canonicalPathAlloc(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) ![]u8 {
    const canonical = Dir.cwd().realPathFileAlloc(
        io,
        path,
        allocator,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse ".";
            const canonical_parent = try Dir.cwd().realPathFileAlloc(
                io,
                parent,
                allocator,
            );
            defer allocator.free(canonical_parent);
            return std.fs.path.join(
                allocator,
                &.{ canonical_parent, std.fs.path.basename(path) },
            );
        },
        else => return err,
    };
    defer allocator.free(canonical);
    return allocator.dupe(u8, canonical);
}

fn rejectOutputAlias(
    allocator: Allocator,
    io: Io,
    output_path: []const u8,
    work_file_path: []const u8,
) !void {
    const output_stat = Dir.cwd().statFile(io, output_path, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (output_stat) |stat| {
        if (stat.kind == .sym_link) return error.OutputPathIsSymlink;
    }

    const canonical_output = try canonicalPathAlloc(
        allocator,
        io,
        output_path,
    );
    defer allocator.free(canonical_output);
    const canonical_work_file = try canonicalPathAlloc(
        allocator,
        io,
        work_file_path,
    );
    defer allocator.free(canonical_work_file);
    if (std.mem.eql(u8, canonical_output, canonical_work_file)) {
        return error.OutputAliasesWorkFile;
    }

    if (output_stat == null or output_stat.?.kind != .file) return;
    const work_stat = Dir.cwd().statFile(io, work_file_path, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (work_stat.kind != .file or
        work_stat.inode != output_stat.?.inode)
    {
        return;
    }

    const output_file = try Dir.cwd().openFile(io, output_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer output_file.close(io);
    const work_file = try Dir.cwd().openFile(io, work_file_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer work_file.close(io);
    if (try artifact_pipeline.sameFileIdentity(io, output_file, work_file)) {
        return error.OutputAliasesWorkFile;
    }
}

const customization_user_data_template =
    \\#cloud-config
    \\hostname: zvmi-freebsd-customizer
    \\users: []
    \\ssh_pwauth: false
    \\packages:
    \\  - azure-agent-2.15.0.1
    \\write_files:
    \\  - path: /etc/rc.conf.d/firstboot_pkg_upgrade
    \\    permissions: "0644"
    \\    content: |
    \\      firstboot_pkg_upgrade_enable="NO"
    \\  - path: /root/zvmi-generalize.sh
    \\    permissions: "0700"
    \\    content: |
    \\      #!/bin/sh
    \\      set -eu
    \\      report_failure()
    \\      {
    \\          status=$?
    \\          trap - EXIT
    \\          if [ "${status}" -eq 0 ]; then
    \\              status=1
    \\          fi
    \\          for output in /dev/console /dev/ttyu0; do
    \\              if [ -w "${output}" ]; then
    \\                  printf 'ZVMI_FREEBSD_CUSTOMIZATION_RESULT @NONCE@ %d\n' \
    \\                      "${status}" >"${output}" || true
    \\              fi
    \\          done
    \\          exit "${status}"
    \\      }
    \\      trap report_failure EXIT
    \\      trap 'exit 1' HUP INT TERM
    \\
    \\      pkg info -e azure-agent
    \\      sysrc waagent_enable=YES
    \\      sysrc sshd_enable=YES
    \\      sysrc nuageinit_enable=YES
    \\      sysrc dumpdev=NO
    \\      sysrc 'ifconfig_DEFAULT=SYNCDHCP accept_rtadv'
    \\      sysrc 'ifconfig_hn0=SYNCDHCP'
    \\      sysrc firstboot_pkg_upgrade_enable=NO
    \\      sysrc -f /boot/loader.conf 'console=comconsole,efi,vidconsole'
    \\      sysrc -f /boot/loader.conf comconsole_speed=115200
    \\      sysrc -f /boot/loader.conf boot_multicons=YES
    \\      sysrc -f /boot/loader.conf boot_serial=YES
    \\
    \\      if [ ! -f /usr/local/etc/waagent.conf ]; then
    \\          cp /usr/local/etc/waagent.conf.sample /usr/local/etc/waagent.conf
    \\      fi
    \\      set_agent_config()
    \\      {
    \\          key=$1
    \\          value=$2
    \\          awk -v key="${key}" -v value="${value}" '
    \\              BEGIN { found = 0 }
    \\              index($0, key "=") == 1 {
    \\                  print key "=" value
    \\                  found = 1
    \\                  next
    \\              }
    \\              { print }
    \\              END {
    \\                  if (!found)
    \\                      print key "=" value
    \\              }
    \\          ' /usr/local/etc/waagent.conf > /usr/local/etc/waagent.conf.zvmi
    \\          mv /usr/local/etc/waagent.conf.zvmi /usr/local/etc/waagent.conf
    \\      }
    \\      set_agent_config Provisioning.Agent auto
    \\      set_agent_config Provisioning.SshHostKeyPairType ed25519
    \\      set_agent_config ResourceDisk.SwapSizeMB 2048
    \\      set_agent_config Logs.Console n
    \\
    \\@ROOT_STORAGE@
    \\      if pw usershow freebsd >/dev/null 2>&1; then
    \\          pw userdel freebsd -r
    \\      fi
    \\      pw lock root
    \\      /usr/local/sbin/waagent -deprovision -force
    \\      pkg clean -ay
    \\      rm -rf /var/cache/pkg/*
    \\      rm -f /var/db/pkg/repo-*.sqlite
    \\
    \\      cat > /etc/rc.d/zvmi_generalize <<'ZVMI_SHUTDOWN'
    \\      #!/bin/sh
    \\      #
    \\      # PROVIDE: zvmi_generalize
    \\      # BEFORE: random
    \\      # KEYWORD: shutdown
    \\      . /etc/rc.subr
    \\      name="zvmi_generalize"
    \\      start_cmd=":"
    \\      stop_cmd="zvmi_generalize_stop"
    \\      zvmi_generalize_stop()
    \\      {
    \\          set -eu
    \\          rm -rf /var/lib/waagent /var/log/azure /var/cache/nuageinit
    \\          rm -rf /var/db/entropy/*
    \\          rm -f /var/log/waagent.log /var/log/nuageinit.log
    \\          rm -f /var/run/waagent.pid
    \\          rm -f /etc/rc.conf.d/hostname
    \\          rm -f /etc/rc.conf.d/network
    \\          rm -f /etc/rc.conf.d/routing
    \\          rm -f /etc/ssh/ssh_host_*
    \\          rm -f /etc/hostid /etc/machine-id
    \\          rm -f /var/db/dhclient.leases.*
    \\          rm -f /root/.*history /root/zvmi-generalize.sh
    \\          touch /firstboot
    \\          rm -f /etc/rc.d/zvmi_generalize
    \\          sync
    \\          for output in /dev/console /dev/ttyu0; do
    \\              if [ -w "${output}" ]; then
    \\                  printf 'ZVMI_FREEBSD_CUSTOMIZATION_RESULT @NONCE@ 0\n' \
    \\                      >"${output}" || true
    \\              fi
    \\          done
    \\      }
    \\      load_rc_config "${name}"
    \\      run_rc_command "$1"
    \\      ZVMI_SHUTDOWN
    \\      chmod 0555 /etc/rc.d/zvmi_generalize
    \\      /usr/sbin/daemon -cf /bin/sh -c \
    \\          '/bin/sleep 30; /sbin/shutdown -p now "zvmi customization complete"'
    \\      trap - EXIT HUP INT TERM
    \\runcmd:
    \\  - /bin/sh /root/zvmi-generalize.sh
    \\
;

const customization_metadata_template =
    \\instance-id: zvmi-build-@NONCE@
    \\local-hostname: zvmi-freebsd-customizer
    \\
;

/// UFS root growth and swap removal. rc.d/growfs recovers the GPT, resizes
/// the last partition, and then runs growfs(8) against the root device named
/// by /etc/fstab. `growfs_swap_size=0` keeps it from adding an OS-disk swap
/// partition, because Azure supplies swap on the resource disk instead.
const ufs_root_storage_script =
    \\      root_fstype=$(mount -p | awk '$2 == "/" { print $3 }')
    \\      test "${root_fstype}" = ufs
    \\      sysrc growfs_enable=YES
    \\      sysrc growfs_swap_size=0
    \\      swapoff -a
    \\      awk '$3 != "swap" { print }' /etc/fstab > /etc/fstab.zvmi
    \\      chmod 0644 /etc/fstab.zvmi
    \\      mv /etc/fstab.zvmi /etc/fstab
    \\      # A UFS root is mounted from /etc/fstab, so dropping that line
    \\      # while stripping swap would produce an unbootable image.
    \\      grep -Eq '@FSTAB_ROOT_PATTERN@' /etc/fstab
;

/// ZFS root growth and swap removal. None of the UFS steps apply: the root
/// dataset is not named in /etc/fstab and growfs(8) cannot grow a pool. After
/// recovering the GPT and resizing the last partition, rc.d/growfs onlines
/// the enlarged vdev with `zpool online -e`; `autoexpand` keeps a later vdev
/// enlargement working without another first-boot pass.
const zfs_root_storage_script =
    \\      root_fstype=$(mount -p | awk '$2 == "/" { print $3 }')
    \\      test "${root_fstype}" = zfs
    \\      root_dataset=$(mount -p | awk '$2 == "/" { print $1 }')
    \\      root_pool=${root_dataset%%/*}
    \\      test "${root_pool}" = @ROOT_POOL@
    \\      # zpool status -x exits 0 even for an unhealthy pool, so compare
    \\      # its report instead of trusting the exit status.
    \\      test "$(zpool status -x "${root_pool}")" = \
    \\          "pool '${root_pool}' is healthy"
    \\      sysrc zfs_enable=YES
    \\      sysrc growfs_enable=YES
    \\      sysrc growfs_swap_size=0
    \\      zpool set autoexpand=on "${root_pool}"
    \\      # A per-instance pool GUID is the ZFS half of identity separation.
    \\      # UFS has no equivalent, so this must not move into shared code.
    \\      sysrc zpool_reguid="${root_pool}"
    \\      swapoff -a
    \\      awk '$3 != "swap" { print }' /etc/fstab > /etc/fstab.zvmi
    \\      chmod 0644 /etc/fstab.zvmi
    \\      mv /etc/fstab.zvmi /etc/fstab
    \\      # The ZFS image never names its root in /etc/fstab, so demanding a
    \\      # root line here - as the UFS profile does - would be wrong.
    \\      # Require instead that nothing swap-like survives, including the
    \\      # swap zvol layouts other FreeBSD ZFS installers produce.
    \\      ! grep -Eq '^[^#].*[[:space:]]swap[[:space:]]' /etc/fstab
    \\      swap_volumes=$(zfs list -H -o name,org.freebsd:swap -t volume |
    \\          awk '$2 == "on" { print $1 }')
    \\      for volume in ${swap_volumes}; do
    \\          zfs destroy "${volume}"
    \\      done
;

const Substitution = struct {
    token: []const u8,
    value: []const u8,
};

fn renderTemplateAlloc(
    allocator: Allocator,
    template: []const u8,
    substitutions: []const Substitution,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var offset: usize = 0;
    scan: while (offset < template.len) {
        if (template[offset] == '@') {
            for (substitutions) |substitution| {
                if (std.mem.startsWith(
                    u8,
                    template[offset..],
                    substitution.token,
                )) {
                    try output.writer.writeAll(substitution.value);
                    offset += substitution.token.len;
                    continue :scan;
                }
            }
        }
        try output.writer.writeByte(template[offset]);
        offset += 1;
    }
    return output.toOwnedSlice();
}

/// Render the filesystem-specific half of the generalization script. The two
/// arms share no text, so a UFS assumption cannot reach the ZFS guest by
/// accident.
fn rootStorageScriptAlloc(
    allocator: Allocator,
    storage: RootStorage,
) ![]u8 {
    return switch (storage) {
        .ufs => |ufs| renderTemplateAlloc(
            allocator,
            ufs_root_storage_script,
            &.{.{
                .token = "@FSTAB_ROOT_PATTERN@",
                .value = ufs.fstab_root_pattern,
            }},
        ),
        .zfs => |zfs| renderTemplateAlloc(
            allocator,
            zfs_root_storage_script,
            &.{.{ .token = "@ROOT_POOL@", .value = zfs.pool }},
        ),
    };
}

fn customizationUserDataAlloc(
    allocator: Allocator,
    storage: RootStorage,
    nonce: []const u8,
) ![]u8 {
    const root_storage = try rootStorageScriptAlloc(allocator, storage);
    defer allocator.free(root_storage);
    return renderTemplateAlloc(
        allocator,
        customization_user_data_template,
        &.{
            .{ .token = "@ROOT_STORAGE@", .value = root_storage },
            .{ .token = "@NONCE@", .value = nonce },
        },
    );
}

fn resolveFirmware(
    allocator: Allocator,
    io: Io,
    args: Args,
) !qemu_host.FirmwarePair {
    return try qemu_host.findFirmwarePairAlloc(allocator, io, .{
        .architecture = args.architecture.guestArchitecture(),
        .explicit_code_path = args.uefi_code_path,
        .explicit_vars_path = args.uefi_vars_path,
        .qemu_path = args.qemu_path,
    }) orelse error.FirmwareNotFound;
}

const TemporaryDirectory = struct {
    allocator: Allocator,
    path: []u8,

    fn create(allocator: Allocator, io: Io, parent: []const u8) !TemporaryDirectory {
        var random: [16]u8 = undefined;
        for (0..16) |_| {
            Io.random(io, &random);
            const hex = std.fmt.bytesToHex(random, .lower);
            const path = try std.fmt.allocPrint(
                allocator,
                "{s}/.zvmi-freebsd-{s}",
                .{ parent, &hex },
            );
            Dir.cwd().createDir(
                io,
                path,
                .fromMode(0o700),
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(path);
                    continue;
                },
                else => {
                    allocator.free(path);
                    return err;
                },
            };
            return .{ .allocator = allocator, .path = path };
        }
        return error.TemporaryDirectoryCollision;
    }

    fn deinit(self: *TemporaryDirectory, io: Io) void {
        Dir.cwd().deleteTree(io, self.path) catch |err| {
            std.debug.print(
                "warning: could not remove temporary directory {s}: {s}\n",
                .{ self.path, @errorName(err) },
            );
        };
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

fn runCommand(io: Io, argv: []const []const u8, failure: anyerror) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer child.kill(io);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return failure,
        else => return failure,
    }
}

fn copyFirmwareBounded(
    io: Io,
    source_path: []const u8,
    destination_path: []const u8,
    max_size: u64,
) !void {
    const source = try Dir.cwd().openFile(io, source_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer source.close(io);
    const stat = try source.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    if (stat.size > max_size) return error.FirmwareTooLarge;

    const destination = try Dir.cwd().createFile(io, destination_path, .{
        .read = true,
        .exclusive = true,
    });
    defer destination.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const length: usize = @intCast(@min(stat.size - offset, buffer.len));
        const read = try source.readPositionalAll(io, buffer[0..length], offset);
        if (read != length) return error.ShortRead;
        try destination.writePositionalAll(io, buffer[0..length], offset);
        offset += length;
    }
    const final_stat = try source.stat(io);
    if (final_stat.kind != .file or
        final_stat.inode != stat.inode or
        final_stat.size != stat.size or
        final_stat.mtime.nanoseconds != stat.mtime.nanoseconds or
        final_stat.ctime.nanoseconds != stat.ctime.nanoseconds)
    {
        return error.FirmwareChanged;
    }
}

fn createSeedIso(
    allocator: Allocator,
    io: Io,
    temporary_path: []const u8,
    xorriso_path: []const u8,
    storage: RootStorage,
    nonce: []const u8,
) ![]u8 {
    const seed_dir = try std.fs.path.join(allocator, &.{ temporary_path, "seed" });
    defer allocator.free(seed_dir);
    try Dir.cwd().createDir(io, seed_dir, .default_dir);
    const metadata_path = try std.fs.path.join(allocator, &.{ seed_dir, "meta-data" });
    defer allocator.free(metadata_path);
    const user_data_path = try std.fs.path.join(allocator, &.{ seed_dir, "user-data" });
    defer allocator.free(user_data_path);
    const seed_iso_path = try std.fs.path.join(allocator, &.{ temporary_path, "seed.iso" });
    errdefer allocator.free(seed_iso_path);

    const metadata = try renderTemplateAlloc(
        allocator,
        customization_metadata_template,
        &.{.{ .token = "@NONCE@", .value = nonce }},
    );
    defer allocator.free(metadata);
    const user_data = try customizationUserDataAlloc(
        allocator,
        storage,
        nonce,
    );
    defer allocator.free(user_data);
    try Dir.cwd().writeFile(io, .{ .sub_path = metadata_path, .data = metadata });
    try Dir.cwd().writeFile(io, .{ .sub_path = user_data_path, .data = user_data });
    try runCommand(io, &.{
        xorriso_path,
        "-as",
        "mkisofs",
        "-quiet",
        "-V",
        "cidata",
        "-J",
        "-r",
        "-o",
        seed_iso_path,
        seed_dir,
    }, error.SeedIsoCreationFailed);
    const seed_stat = try Dir.cwd().statFile(io, seed_iso_path, .{
        .follow_symlinks = false,
    });
    if (seed_stat.kind != .file) return error.NotRegularFile;
    if (seed_stat.size > seed_iso_max_size) return error.SeedIsoTooLarge;
    const seed = try artifact_pipeline.hashFile(io, seed_iso_path);
    if (seed.size != seed_stat.size) return error.SeedIsoChanged;
    return seed_iso_path;
}

fn resolveAccel(
    io: Io,
    requested: Accel,
    architecture: Architecture,
) !Accel {
    if (requested != .auto) return requested;
    if (builtin.cpu.arch == architecture.hostCpu()) {
        Dir.cwd().access(
            io,
            "/dev/kvm",
            .{ .read = true, .write = true },
        ) catch return .tcg;
        return .kvm;
    }
    return .tcg;
}

const SerialResult = enum { none, success, failure };

fn readSerialResult(
    io: Io,
    path: []const u8,
    success_marker: []const u8,
    result_marker: []const u8,
) !SerialResult {
    const file = Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return .none,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    const length: usize = @intCast(@min(stat.size, serial_tail_size));
    var buffer: [serial_tail_size]u8 = undefined;
    const offset = stat.size - length;
    const read = try file.readPositionalAll(io, buffer[0..length], offset);
    const bytes = buffer[0..read];
    if (std.mem.indexOf(u8, bytes, success_marker) != null) return .success;
    if (std.mem.indexOf(u8, bytes, result_marker) != null) return .failure;
    return .none;
}

fn printSerialTail(io: Io, path: []const u8) void {
    const file = Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch return;
    defer file.close(io);
    const stat = file.stat(io) catch return;
    const length: usize = @intCast(@min(stat.size, serial_tail_size));
    var buffer: [serial_tail_size]u8 = undefined;
    const read = file.readPositionalAll(
        io,
        buffer[0..length],
        stat.size - length,
    ) catch return;
    std.debug.print("FreeBSD serial output tail:\n{s}\n", .{buffer[0..read]});
}

fn escapeQemuDriveValue(
    allocator: Allocator,
    value: []const u8,
) ![]u8 {
    var escaped: std.Io.Writer.Allocating = .init(allocator);
    defer escaped.deinit();
    for (value) |byte| {
        try escaped.writer.writeByte(byte);
        if (byte == ',') try escaped.writer.writeByte(',');
    }
    return escaped.toOwnedSlice();
}

fn runGuestCustomization(
    allocator: Allocator,
    io: Io,
    args: Args,
    uefi_code_path: []const u8,
    image_path: []const u8,
    seed_iso_path: []const u8,
    vars_path: []const u8,
    serial_path: []const u8,
    nonce: []const u8,
) !void {
    const accel = try resolveAccel(io, args.accel, args.architecture);
    const machine = args.architecture.machineArg(accel);
    const cpu = args.architecture.cpuArg(accel);
    const escaped_code = try escapeQemuDriveValue(allocator, uefi_code_path);
    defer allocator.free(escaped_code);
    const escaped_vars = try escapeQemuDriveValue(allocator, vars_path);
    defer allocator.free(escaped_vars);
    const code_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,readonly=on,file={s}",
        .{escaped_code},
    );
    defer allocator.free(code_drive);
    const vars_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,file={s}",
        .{escaped_vars},
    );
    defer allocator.free(vars_drive);
    const serial = try std.fmt.allocPrint(allocator, "file:{s}", .{serial_path});
    defer allocator.free(serial);

    const image = try Dir.cwd().openFile(io, image_path, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer image.close(io);
    const seed = try Dir.cwd().openFile(io, seed_iso_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer seed.close(io);

    const deadline = Io.Clock.awake.now(io).addDuration(
        .fromSeconds(args.customization_timeout_seconds),
    );
    var spawned = try qmp.spawnAndConnect(allocator, io, .{
        .binary = args.qemu_path,
        .extra_args = &.{
            "-machine",
            machine,
            "-cpu",
            cpu,
            "-smp",
            "2",
            "-m",
            "2048",
            "-display",
            "none",
            "-no-reboot",
            "-no-shutdown",
            "-monitor",
            "none",
            "-serial",
            serial,
            "-drive",
            code_drive,
            "-drive",
            vars_drive,
            "-drive",
            "file=/proc/self/fd/0,format=qcow2,if=virtio",
            "-drive",
            "file=/proc/self/fd/1,format=raw,if=virtio,readonly=on",
            "-netdev",
            "user,id=net0",
            "-device",
            "virtio-net-pci,netdev=net0,romfile=",
            "-device",
            "virtio-rng-pci",
        },
        .stdin = .{ .file = image },
        .stdout = .{ .file = seed },
        .stderr = .inherit,
        .connect_timeout = .fromSeconds(
            @min(
                args.customization_timeout_seconds,
                qmp_connect_timeout_seconds,
            ),
        ),
    });
    var child_waited = false;
    defer {
        if (!child_waited) spawned.kill();
        spawned.deinit();
    }

    const success_marker = try std.fmt.allocPrint(
        allocator,
        "{s} {s} 0",
        .{ customization_result_prefix, nonce },
    );
    defer allocator.free(success_marker);
    const result_marker = try std.fmt.allocPrint(
        allocator,
        "{s} {s} ",
        .{ customization_result_prefix, nonce },
    );
    defer allocator.free(result_marker);
    var success_seen = false;
    var success_deadline: ?Io.Timestamp = null;

    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        switch (try readSerialResult(
            io,
            serial_path,
            success_marker,
            result_marker,
        )) {
            .none => {},
            .failure => return error.GuestCustomizationFailed,
            .success => {
                if (!success_seen) {
                    success_seen = true;
                    success_deadline = Io.Clock.awake.now(io).addDuration(
                        .fromSeconds(120),
                    );
                }
            },
        }

        const running = spawned.client.queryRunningUntil(deadline) catch |err| {
            spawned.kill();
            child_waited = true;
            return err;
        };
        if (!running) {
            switch (try readSerialResult(
                io,
                serial_path,
                success_marker,
                result_marker,
            )) {
                .none => {},
                .failure => return error.GuestCustomizationFailed,
                .success => success_seen = true,
            }
            if (!success_seen) return error.GuestCustomizationFailed;
            var reply = try spawned.client.executeUntil(
                "quit",
                null,
                deadline,
            );
            defer reply.deinit();
            if (reply.err != null) return error.QemuCustomizationFailed;
            const term = try spawned.waitUntil(deadline);
            child_waited = true;
            switch (term) {
                .exited => |code| if (code != 0) {
                    return error.QemuCustomizationFailed;
                },
                else => return error.QemuCustomizationFailed,
            }
            return;
        }
        if (success_deadline) |grace| {
            if (Io.Clock.awake.now(io).nanoseconds >= grace.nanoseconds) {
                return error.GuestShutdownTimedOut;
            }
        }
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.GuestCustomizationTimedOut;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help_text });
        std.process.exit(1);
    };
    const expected_source = artifact_pipeline.parseSha256(
        args.source_sha256,
    ) catch {
        std.debug.print("error: invalid --source-sha256\n", .{});
        std.process.exit(1);
    };
    const profile = args.profile;

    try Dir.cwd().createDirPath(io, args.work_dir);
    if (std.fs.path.dirname(args.output)) |parent| {
        try Dir.cwd().createDirPath(io, parent);
    }

    const cached_source = try std.fs.path.join(
        allocator,
        &.{ args.work_dir, profile.source_name },
    );
    defer allocator.free(cached_source);
    try rejectOutputAlias(
        allocator,
        io,
        args.output,
        cached_source,
    );
    const compressed_source = if (args.source) |path| path else blk: {
        var curl = artifact_pipeline.CurlDownloader{
            .executable_path = args.curl_path,
        };
        const acquired = try artifact_pipeline.acquireVerified(
            allocator,
            io,
            .{
                .url = profile.source_url,
                .destination_path = cached_source,
                .expected_sha256 = expected_source,
                .max_size = source_max_size,
            },
            curl.downloader(),
        );
        std.debug.print(
            "{s} compressed source: {s}\n",
            .{
                if (acquired.reused_cache) "Using cached" else "Downloaded",
                acquired.artifact.path,
            },
        );
        break :blk cached_source;
    };

    var temporary = try TemporaryDirectory.create(
        allocator,
        io,
        args.work_dir,
    );
    defer temporary.deinit(io);
    const decompressed_path = try std.fs.path.join(
        allocator,
        &.{ temporary.path, "source.qcow2" },
    );
    defer allocator.free(decompressed_path);
    std.debug.print("Decompressing and validating FreeBSD source...\n", .{});
    const decompressed = try artifact_pipeline.decompressXz(
        allocator,
        io,
        .{
            .input_path = compressed_source,
            .expected_input_sha256 = expected_source,
            .output_path = decompressed_path,
            .max_output_size = image_max_size,
            .max_memory_size = xz_memory_limit,
            .xz_path = args.xz_path,
        },
    );

    const finalized = if (args.base_only) blk: {
        std.debug.print("Finalizing verified upstream base QCOW2...\n", .{});
        break :blk try artifact_pipeline.finalizeQcow2(
            allocator,
            io,
            .{
                .input_path = decompressed.path,
                .expected_input_sha256 = decompressed.sha256,
                .max_input_size = image_max_size,
                .source_format = .qcow2,
                .expected_virtual_size = profile.virtual_size,
                .max_virtual_size = profile.virtual_size,
                .output_path = args.output,
                .max_output_size = finalized_image_max_size,
                .qemu_img_path = args.qemu_img_path,
                .compression = .zstd,
            },
        );
    } else blk: {
        var firmware = try resolveFirmware(allocator, io, args);
        defer firmware.deinit(allocator);
        const mutable_path = try std.fs.path.join(
            allocator,
            &.{ temporary.path, "customized.qcow2" },
        );
        defer allocator.free(mutable_path);
        const vars_path = try std.fs.path.join(
            allocator,
            &.{ temporary.path, "uefi-vars.fd" },
        );
        defer allocator.free(vars_path);
        const code_path = try std.fs.path.join(
            allocator,
            &.{ temporary.path, "uefi-code.fd" },
        );
        defer allocator.free(code_path);
        const serial_path = try std.fs.path.join(
            allocator,
            &.{ temporary.path, "serial.log" },
        );
        defer allocator.free(serial_path);

        std.debug.print("Preparing mutable FreeBSD QCOW2...\n", .{});
        _ = try artifact_pipeline.finalizeQcow2(
            allocator,
            io,
            .{
                .input_path = decompressed.path,
                .expected_input_sha256 = decompressed.sha256,
                .max_input_size = image_max_size,
                .source_format = .qcow2,
                .expected_virtual_size = profile.virtual_size,
                .max_virtual_size = profile.virtual_size,
                .output_path = mutable_path,
                .max_output_size = finalized_image_max_size,
                .qemu_img_path = args.qemu_img_path,
                .compression = .zstd,
            },
        );
        try copyFirmwareBounded(
            io,
            firmware.code_path,
            code_path,
            firmware_max_size,
        );
        try copyFirmwareBounded(
            io,
            firmware.vars_path,
            vars_path,
            firmware_max_size,
        );

        var nonce_bytes: [16]u8 = undefined;
        Io.random(io, &nonce_bytes);
        const nonce_hex = std.fmt.bytesToHex(nonce_bytes, .lower);
        const seed_iso_path = try createSeedIso(
            allocator,
            io,
            temporary.path,
            args.xorriso_path,
            profile.root_storage,
            &nonce_hex,
        );
        defer allocator.free(seed_iso_path);

        std.debug.print(
            "Customizing FreeBSD {s} {s} under UEFI QEMU ({s})...\n",
            .{
                @tagName(args.architecture),
                @tagName(profile.rootFilesystem()),
                @tagName(try resolveAccel(io, args.accel, args.architecture)),
            },
        );
        runGuestCustomization(
            allocator,
            io,
            args,
            code_path,
            mutable_path,
            seed_iso_path,
            vars_path,
            serial_path,
            &nonce_hex,
        ) catch |err| {
            std.debug.print(
                "error: FreeBSD guest customization failed: {s}\n",
                .{@errorName(err)},
            );
            printSerialTail(io, serial_path);
            return err;
        };

        const customized = try artifact_pipeline.hashFile(io, mutable_path);
        std.debug.print("Finalizing generalized standalone zstd QCOW2...\n", .{});
        break :blk try artifact_pipeline.finalizeQcow2(
            allocator,
            io,
            .{
                .input_path = mutable_path,
                .expected_input_sha256 = customized.sha256,
                .max_input_size = finalized_image_max_size,
                .source_format = .qcow2,
                .expected_virtual_size = profile.virtual_size,
                .max_virtual_size = profile.virtual_size,
                .output_path = args.output,
                .max_output_size = finalized_image_max_size,
                .qemu_img_path = args.qemu_img_path,
                .compression = .zstd,
            },
        );
    };
    const finalized_sha256 = artifact_pipeline.formatSha256(
        finalized.artifact.sha256,
    );
    std.debug.print(
        "Built {s} ({s} {s} {s}, {d} bytes, virtual size {d}, SHA-256 {s})\n",
        .{
            finalized.artifact.path,
            @tagName(profile.architecture),
            @tagName(profile.rootFilesystem()),
            @tagName(profile.flavor),
            finalized.artifact.size,
            finalized.virtual_size,
            &finalized_sha256,
        },
    );
}

test "FreeBSD builder defaults pin the official release source" {
    const args = try parseArgs(&.{});
    const profile = findProfile(.aarch64, .ufs, .full).?;
    try std.testing.expect(args.source == null);
    try std.testing.expectEqual(Architecture.aarch64, args.architecture);
    try std.testing.expectEqual(RootFilesystem.ufs, args.root_filesystem);
    try std.testing.expectEqual(Flavor.full, args.flavor);
    try std.testing.expectEqual(profile, args.profile);
    try std.testing.expectEqualStrings(
        profile.source_sha256,
        args.source_sha256,
    );
    try std.testing.expectEqualStrings(profile.output, args.output);
    try std.testing.expectEqualStrings("curl", args.curl_path);
    try std.testing.expectEqualStrings("xz", args.xz_path);
    try std.testing.expectEqualStrings("qemu-img", args.qemu_img_path);
    try std.testing.expectEqualStrings("qemu-system-aarch64", args.qemu_path);
    try std.testing.expectEqualStrings("xorriso", args.xorriso_path);
    try std.testing.expectEqual(Accel.auto, args.accel);
    try std.testing.expectEqual(
        default_customization_timeout_seconds,
        args.customization_timeout_seconds,
    );
    try std.testing.expect(!args.base_only);
    _ = try artifact_pipeline.parseSha256(args.source_sha256);
}

test "FreeBSD builder selects pinned x86_64 defaults" {
    const args = try parseArgs(&.{ "--architecture", "x86_64" });
    const profile = findProfile(.x86_64, .ufs, .full).?;
    try std.testing.expectEqual(Architecture.x86_64, args.architecture);
    try std.testing.expectEqualStrings(
        profile.source_sha256,
        args.source_sha256,
    );
    try std.testing.expectEqualStrings(profile.output, args.output);
    try std.testing.expectEqualStrings(profile.work_dir, args.work_dir);
    try std.testing.expectEqualStrings("qemu-system-x86_64", args.qemu_path);
    try std.testing.expectEqualStrings(
        "qemu64",
        args.architecture.cpuArg(.tcg),
    );
    try std.testing.expectEqualStrings(
        "host",
        args.architecture.cpuArg(.kvm),
    );
}

test "FreeBSD builder selects pinned ZFS defaults per architecture" {
    const aarch64 = try parseArgs(&.{ "--filesystem", "zfs" });
    try std.testing.expectEqual(RootFilesystem.zfs, aarch64.root_filesystem);
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-aarch64.zfs.qcow2",
        aarch64.output,
    );
    try std.testing.expectEqualStrings(
        ".scratch/generalized-freebsd15-aarch64-zfs",
        aarch64.work_dir,
    );
    try std.testing.expectEqualStrings(
        "0911a033b0a5d060486f92e534f3482c6a2ab96af6abb8a60683eeb24f6746af",
        aarch64.source_sha256,
    );
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        aarch64.profile.source_name,
    );
    try std.testing.expectEqual(
        @as(u64, 6_477_643_776),
        aarch64.profile.virtual_size,
    );
    try std.testing.expectEqualStrings(
        "qemu-system-aarch64",
        aarch64.qemu_path,
    );

    const x86_64 = try parseArgs(&.{
        "--architecture", "x86_64",
        "--filesystem",   "zfs",
    });
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-x86_64.zfs.qcow2",
        x86_64.output,
    );
    try std.testing.expectEqualStrings(
        ".scratch/generalized-freebsd15-x86_64-zfs",
        x86_64.work_dir,
    );
    try std.testing.expectEqualStrings(
        "4159e137d4a78f46b62d3523edd9a4dc79fd0cdcf17e34e531342f52333f4131",
        x86_64.source_sha256,
    );
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        x86_64.profile.source_name,
    );
    try std.testing.expectEqual(
        @as(u64, 6_477_840_384),
        x86_64.profile.virtual_size,
    );
}

test "FreeBSD profile table is complete, unique, and pinned" {
    var seen: usize = 0;
    for (std.enums.values(Architecture)) |architecture| {
        for (std.enums.values(RootFilesystem)) |root_filesystem| {
            for (std.enums.values(Flavor)) |flavor| {
                const profile = findProfile(
                    architecture,
                    root_filesystem,
                    flavor,
                ) orelse return error.MissingProfile;
                try std.testing.expectEqual(architecture, profile.architecture);
                try std.testing.expectEqual(
                    root_filesystem,
                    profile.rootFilesystem(),
                );
                try std.testing.expectEqual(flavor, profile.flavor);
                seen += 1;
            }
        }
    }
    try std.testing.expectEqual(profiles.len, seen);

    for (&profiles, 0..) |*profile, index| {
        _ = try artifact_pipeline.parseSha256(profile.source_sha256);
        try std.testing.expect(std.mem.startsWith(
            u8,
            profile.source_url,
            "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/",
        ));
        try std.testing.expect(std.mem.endsWith(
            u8,
            profile.source_url,
            profile.source_name,
        ));
        try std.testing.expect(std.mem.indexOf(
            u8,
            profile.source_name,
            "BASIC-CLOUDINIT",
        ) != null);
        // The upstream file name has to agree with the profile's filesystem,
        // or a ZFS build would silently generalize a UFS image.
        try std.testing.expect(std.mem.indexOf(
            u8,
            profile.source_name,
            switch (profile.rootFilesystem()) {
                .ufs => "-ufs.qcow2.xz",
                .zfs => "-zfs.qcow2.xz",
            },
        ) != null);
        try std.testing.expectEqualStrings(
            switch (profile.rootFilesystem()) {
                .ufs => ".qcow2",
                .zfs => ".zfs.qcow2",
            },
            profile.output[profile.output.len - switch (profile.rootFilesystem()) {
                .ufs => ".qcow2".len,
                .zfs => ".zfs.qcow2".len,
            } ..],
        );
        // Azure fixed VHDs derived from these images require a 512-byte
        // aligned virtual size, so a mistyped pin must fail here.
        try std.testing.expect(profile.virtual_size > 0);
        try std.testing.expectEqual(
            @as(u64, 0),
            profile.virtual_size % 512,
        );
        for (profiles[index + 1 ..]) |*other| {
            try std.testing.expect(!std.mem.eql(u8, profile.output, other.output));
            try std.testing.expect(!std.mem.eql(
                u8,
                profile.work_dir,
                other.work_dir,
            ));
            try std.testing.expect(!std.mem.eql(
                u8,
                profile.source_sha256,
                other.source_sha256,
            ));
        }
    }
}

test "FreeBSD builder parses explicit source and tool paths" {
    const args = try parseArgs(&.{
        "--architecture",
        "x86_64",
        "--source",
        "base.qcow2.xz",
        "--source-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--output",
        "out.qcow2",
        "--work-dir",
        "work",
        "--curl",
        "/tools/curl",
        "--xz",
        "/tools/xz",
        "--qemu-img",
        "/tools/qemu-img",
        "--qemu",
        "/tools/qemu-system-x86_64",
        "--xorriso",
        "/tools/xorriso",
        "--uefi-code",
        "/firmware/code.fd",
        "--uefi-vars",
        "/firmware/vars.fd",
        "--accel",
        "tcg",
        "--timeout",
        "900",
        "--base-only",
    });
    try std.testing.expectEqual(Architecture.x86_64, args.architecture);
    try std.testing.expectEqualStrings("base.qcow2.xz", args.source.?);
    try std.testing.expectEqualStrings("out.qcow2", args.output);
    try std.testing.expectEqualStrings("work", args.work_dir);
    try std.testing.expectEqualStrings("/tools/curl", args.curl_path);
    try std.testing.expectEqualStrings("/tools/xz", args.xz_path);
    try std.testing.expectEqualStrings("/tools/qemu-img", args.qemu_img_path);
    try std.testing.expectEqualStrings("/tools/qemu-system-x86_64", args.qemu_path);
    try std.testing.expectEqualStrings("/tools/xorriso", args.xorriso_path);
    try std.testing.expectEqualStrings("/firmware/code.fd", args.uefi_code_path.?);
    try std.testing.expectEqualStrings("/firmware/vars.fd", args.uefi_vars_path.?);
    try std.testing.expectEqual(Accel.tcg, args.accel);
    try std.testing.expectEqual(@as(u32, 900), args.customization_timeout_seconds);
    try std.testing.expect(args.base_only);
}

test "FreeBSD builder rejects malformed arguments" {
    try std.testing.expectError(
        error.MissingValue,
        parseArgs(&.{"--source"}),
    );
    try std.testing.expectError(
        error.UnexpectedArgument,
        parseArgs(&.{"--unknown"}),
    );
    try std.testing.expectError(
        error.InvalidAccelerator,
        parseArgs(&.{ "--accel", "invalid" }),
    );
    try std.testing.expectError(
        error.InvalidArchitecture,
        parseArgs(&.{ "--architecture", "amd64" }),
    );
    try std.testing.expectError(
        error.InvalidRootFilesystem,
        parseArgs(&.{ "--filesystem", "zfs-root" }),
    );
    try std.testing.expectError(
        error.InvalidFlavor,
        parseArgs(&.{ "--flavor", "core" }),
    );
    try std.testing.expectError(
        error.MissingValue,
        parseArgs(&.{"--filesystem"}),
    );
    try std.testing.expectError(
        error.InvalidTimeout,
        parseArgs(&.{ "--timeout", "0" }),
    );
    try std.testing.expectError(
        error.IncompleteFirmwareOverride,
        parseArgs(&.{ "--uefi-code", "code.fd" }),
    );
}

test "FreeBSD builder rejects output aliases before acquisition" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_length];
    const cached = try std.fs.path.join(
        allocator,
        &.{ root, findProfile(.aarch64, .ufs, .full).?.source_name },
    );
    defer allocator.free(cached);
    const output = try std.fs.path.join(allocator, &.{ root, "output.qcow2" });
    defer allocator.free(output);

    try std.testing.expectError(
        error.OutputAliasesWorkFile,
        rejectOutputAlias(allocator, io, cached, cached),
    );
    try rejectOutputAlias(allocator, io, output, cached);

    try temporary.dir.symLink(
        io,
        findProfile(.aarch64, .ufs, .full).?.source_name,
        "output.qcow2",
        .{},
    );
    try std.testing.expectError(
        error.OutputPathIsSymlink,
        rejectOutputAlias(allocator, io, output, cached),
    );
}

/// Properties every generalized FreeBSD guest must carry regardless of
/// profile. A ZFS image that quietly lost one of these would still boot, so
/// the contract is asserted here instead of being re-read by hand.
const generalized_guest_contract = [_][]const u8{
    // Key-only SSH with no default account.
    "ssh_pwauth: false",
    "users: []",
    "pw userdel freebsd -r",
    "pw lock root",
    "sysrc sshd_enable=YES",
    // nuageinit provisioning and the pinned Azure Agent.
    "azure-agent-2.15.0.1",
    "sysrc nuageinit_enable=YES",
    "sysrc waagent_enable=YES",
    "set_agent_config Provisioning.Agent auto",
    "set_agent_config Provisioning.SshHostKeyPairType ed25519",
    "set_agent_config ResourceDisk.SwapSizeMB 2048",
    // Generic and Hyper-V DHCP.
    "sysrc 'ifconfig_DEFAULT=SYNCDHCP accept_rtadv'",
    "sysrc 'ifconfig_hn0=SYNCDHCP'",
    // Azure serial console settings.
    "console=comconsole,efi,vidconsole",
    "comconsole_speed=115200",
    "boot_multicons=YES",
    "boot_serial=YES",
    "/dev/console /dev/ttyu0",
    // Cleared instance identity and a clean shutdown.
    "waagent -deprovision -force",
    "rm -f /etc/ssh/ssh_host_*",
    "rm -f /etc/hostid /etc/machine-id",
    "rm -rf /var/lib/waagent /var/log/azure /var/cache/nuageinit",
    "touch /firstboot",
    "/usr/sbin/daemon -cf",
    "/sbin/shutdown -p now",
    // First-boot growth is part of the contract for both filesystems.
    "sysrc growfs_enable=YES",
    "sysrc growfs_swap_size=0",
    "swapoff -a",
};

test "every FreeBSD profile seed honors the generalized guest contract" {
    const allocator = std.testing.allocator;
    const nonce = "0123456789abcdef";
    for (&profiles) |*profile| {
        const user_data = try customizationUserDataAlloc(
            allocator,
            profile.root_storage,
            nonce,
        );
        defer allocator.free(user_data);

        try std.testing.expect(std.mem.indexOf(
            u8,
            user_data,
            "@",
        ) == null);
        for (&generalized_guest_contract) |required| {
            if (std.mem.indexOf(u8, user_data, required) == null) {
                std.debug.print(
                    "{s} {s} seed is missing {s}\n",
                    .{
                        @tagName(profile.architecture),
                        @tagName(profile.rootFilesystem()),
                        required,
                    },
                );
                return error.GuestContractViolated;
            }
        }
        const expected_result =
            customization_result_prefix ++ " " ++ nonce ++ " 0";
        try std.testing.expect(std.mem.indexOf(
            u8,
            user_data,
            expected_result,
        ) != null);
    }
}

test "FreeBSD root storage handling never crosses filesystems" {
    const allocator = std.testing.allocator;
    const ufs = try rootStorageScriptAlloc(allocator, ufs_root_storage);
    defer allocator.free(ufs);
    const zfs = try rootStorageScriptAlloc(allocator, zfs_root_storage);
    defer allocator.free(zfs);

    // The UFS arm grows a filesystem and must keep its fstab root line; it
    // must never reach for pool tooling.
    try std.testing.expect(std.mem.indexOf(u8, ufs, "= ufs") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        ufs,
        "grep -Eq '^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]' /etc/fstab",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, ufs, "zpool") == null);
    try std.testing.expect(std.mem.indexOf(u8, ufs, "zfs ") == null);

    // The ZFS arm grows a pool vdev, re-randomizes the pool GUID, and must
    // never assert the UFS-only fstab root line.
    try std.testing.expect(std.mem.indexOf(u8, zfs, "= zfs") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        zfs,
        "zpool set autoexpand=on \"${root_pool}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        zfs,
        "sysrc zpool_reguid=\"${root_pool}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "test \"${root_pool}\" = zroot") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        zfs,
        "is healthy",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "org.freebsd:swap") != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "zfs destroy") != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "growfs -y") == null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "ufs") == null);

    // Both arms strip swap, and neither may leave a swap mount behind.
    for ([_][]const u8{ ufs, zfs }) |script| {
        try std.testing.expect(std.mem.indexOf(u8, script, "swapoff -a") != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            script,
            "awk '$3 != \"swap\" { print }' /etc/fstab",
        ) != null);
        try std.testing.expect(std.mem.indexOf(u8, script, "@") == null);
    }
}

test "FreeBSD seed embeds only the selected profile's root storage" {
    const allocator = std.testing.allocator;
    const nonce = "fedcba9876543210";
    const ufs_seed = try customizationUserDataAlloc(
        allocator,
        ufs_root_storage,
        nonce,
    );
    defer allocator.free(ufs_seed);
    const zfs_seed = try customizationUserDataAlloc(
        allocator,
        zfs_root_storage,
        nonce,
    );
    defer allocator.free(zfs_seed);

    try std.testing.expect(std.mem.indexOf(u8, ufs_seed, "zpool") == null);
    try std.testing.expect(std.mem.indexOf(u8, zfs_seed, "zpool") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        zfs_seed,
        "[[:space:]]+ufs[[:space:]]",
    ) == null);

    // The substituted block must stay inside the cloud-config script literal,
    // so every rendered line keeps the six-space `content: |` indentation.
    var lines = std.mem.splitScalar(u8, zfs_seed, '\n');
    var inside = false;
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "      set_agent_config Logs.Console n")) {
            inside = true;
            continue;
        }
        if (!inside) continue;
        if (std.mem.startsWith(u8, line, "      if pw usershow freebsd")) break;
        if (line.len == 0) continue;
        try std.testing.expect(std.mem.startsWith(u8, line, "      "));
    } else return error.RootStorageBlockNotTerminated;
}

test "QEMU drive values escape commas" {
    const escaped = try escapeQemuDriveValue(
        std.testing.allocator,
        "work,dir/vars.fd",
    );
    defer std.testing.allocator.free(escaped);
    try std.testing.expectEqualStrings("work,,dir/vars.fd", escaped);
}

test "serial result requires the nonce and successful status" {
    const io = std.testing.io;
    const path = "test-freebsd-customization-serial.log";
    defer Dir.cwd().deleteFile(io, path) catch {};
    const nonce = "abcdef";
    const success = customization_result_prefix ++ " abcdef 0";
    const result = customization_result_prefix ++ " abcdef ";

    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = customization_result_prefix ++ " other 0\n",
    });
    try std.testing.expectEqual(
        SerialResult.none,
        try readSerialResult(io, path, success, result),
    );
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = customization_result_prefix ++ " " ++ nonce ++ " 7\n",
    });
    try std.testing.expectEqual(
        SerialResult.failure,
        try readSerialResult(io, path, success, result),
    );
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = success ++ "\n",
    });
    try std.testing.expectEqual(
        SerialResult.success,
        try readSerialResult(io, path, success, result),
    );
}
