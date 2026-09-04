//! The explicit runtime contract for the Ubuntu 26.04 core appliance.
//!
//! Issue #677 step 2 asks a question the closure work cannot start without:
//! what, exactly, does this appliance need? Not "what does it currently have"
//! -- that is the package lock -- but which packages, files, commands,
//! libraries, kernel modules, devices, mounts, configuration, and mutable
//! paths the shipped behaviors actually stand on. This module is that answer,
//! written once, machine-readable, and derived from behavior rather than from
//! whatever the current root happens to contain.
//!
//! Three properties make it useful rather than decorative:
//!
//!   * Every entry names the behavior it exists for. A requirement nobody can
//!     attribute to a behavior is a convenience, and convenience is what step 3
//!     removes.
//!   * Every entry names its *audience*. `guest_runtime` is the appliance's own
//!     need; `build_tooling` is needed only while the image is assembled;
//!     `acceptance_only` is needed only by the test harness. Conflating those
//!     three is exactly how a minimization ends up retaining a tool because a
//!     test used it, which #677 calls out by name.
//!   * Every entry names when it can first be observed. An image-present entry
//!     is checkable in the built root before anything boots; a runtime entry
//!     only exists in a booted guest. Checking the wrong one at the wrong stage
//!     produces either a false pass or a false failure.
//!
//! The module depends on `std` alone, because the same tables are compiled
//! into the static guest probe (`tests/ubuntu2604_runtime_contract_probe.zig`)
//! that evaluates them inside a running guest over SSH. The probe replaces the
//! shell utilities acceptance used to reach for -- `findmnt`, `od`, `grep`,
//! `mountpoint`, `modprobe` -- so package minimization is never pressured into
//! keeping a binary that only a test needed. The JSON document, the provenance
//! binding, and the built-root gate live in `runtime_contract_document.zig`,
//! which is host-only and may depend on the release tooling.

const std = @import("std");

/// The shipped behaviors #677 enumerates. Every requirement is attributed to
/// exactly one of them, so "why is this here" always has an answer that is not
/// "it was already installed".
pub const Behavior = enum {
    /// `mizinit` as PID 1, including shutdown and reboot handling.
    pid1_lifecycle,
    /// `azagent` Azure provisioning and WireServer readiness.
    azure_provisioning,
    /// Key-only OpenSSH access and host-key generation.
    ssh_key_only,
    /// The provisioned administrator shell and passwordless privilege path.
    admin_privilege,
    /// Root growth, resource disk, and managed data disk behavior.
    storage_policy,
    /// Secure Boot, vTPM, kernel lockdown, and signed module loading.
    platform_trust,
    /// BinderFS, Binder device use, and the DMA heap.
    binder_workload,
    /// Diagnostics required to operate or recover the appliance.
    diagnostics,
    /// `ca-certificates` and its trust store.
    trust_store,
    /// The provenance payload a published image must be able to account for.
    provenance,

    pub fn key(self: Behavior) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Behavior {
        return std.meta.stringToEnum(Behavior, text);
    }
};

/// Who needs the entry. This is the distinction #677 asks for in as many words:
/// "Acceptance commands are not automatically runtime requirements."
pub const Audience = enum {
    /// The appliance itself needs it in the published image.
    guest_runtime,
    /// Only the build needs it; step 4 moves these out of the final guest.
    build_tooling,
    /// Only the acceptance harness needs it. Nothing may be retained solely to
    /// satisfy one of these, which is why the guest probe reports them without
    /// requiring them.
    acceptance_only,

    pub fn key(self: Audience) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Audience {
        return std.meta.stringToEnum(Audience, text);
    }
};

/// What the entry is, which also decides how it is checked.
pub const Kind = enum {
    /// A dpkg package that must appear in the shipped exact lock.
    package,
    /// A metapackage that is resolved to decide which exact binary packages
    /// the build installs, and is then never installed itself.
    ///
    /// Issue #677 step 4 asks for "exact versioned kernel image/module
    /// packages over convenience metapackages". A literal version pinned into
    /// this repository would satisfy the letter of that and break its point:
    /// the next security kernel would need a source edit, and until someone
    /// made it the appliance would ship a known-stale kernel. A selector keeps
    /// Canonical's own security-update selection -- the metapackage is exactly
    /// the statement "this is the current Azure kernel" -- while installing
    /// only the two versioned binary packages the appliance boots on. The
    /// `expect` field carries the comma-separated name templates the selection
    /// must produce, `*` standing for the kernel release it resolved to.
    package_selector,
    /// An executable file.
    command,
    /// A regular file.
    file,
    /// A directory.
    directory,
    /// A symbolic link whose target is part of the contract.
    symlink,
    /// A configuration file whose contents carry a required marker.
    config,
    /// A directory the running appliance writes to.
    mutable_path,
    /// A kernel module that must be loaded and untainted.
    kernel_module,
    /// A character device node the appliance opens.
    device,
    /// A mount point, with the filesystem type it must carry.
    mount,
    /// The CA bundle, checked for a certificate marker rather than existence.
    trust_store,
    /// PID 1 itself: `/proc/1/exe` must resolve to the named program.
    pid1,
    /// UEFI Secure Boot reported as enabled by firmware.
    secure_boot,
    /// Kernel lockdown engaged at integrity or confidentiality.
    kernel_lockdown,

    pub fn key(self: Kind) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Kind {
        return std.meta.stringToEnum(Kind, text);
    }

    /// Whether a built root, still a host tree, can be asked about this kind.
    pub fn checkableInRoot(self: Kind) bool {
        return switch (self) {
            .command, .file, .directory, .symlink, .config, .trust_store => true,
            .package,
            .package_selector,
            .mutable_path,
            .kernel_module,
            .device,
            .mount,
            .pid1,
            .secure_boot,
            .kernel_lockdown,
            => false,
        };
    }

    /// Whether the static guest probe evaluates this kind.
    pub fn probeable(self: Kind) bool {
        return self != .package and self != .package_selector;
    }
};

/// When the entry can first be observed.
pub const Presence = enum {
    /// Already in the built root, before anything boots.
    image,
    /// Created by the running appliance; only a booted guest has it.
    runtime,

    pub fn key(self: Presence) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Presence {
        return std.meta.stringToEnum(Presence, text);
    }
};

pub const Requirement = struct {
    /// Stable identifier. It is what a probe line, a failure message, and a
    /// future budget review all name, so it never encodes a path.
    id: []const u8,
    kind: Kind,
    /// Path, package name, or module name, depending on `kind`.
    target: []const u8,
    behavior: Behavior,
    audience: Audience = .guest_runtime,
    presence: Presence = .image,
    /// Kind-specific expectation: the filesystem type for `mount`, the link
    /// target for `symlink`, and a required substring for `config` and
    /// `trust_store`. Empty when the kind carries no extra expectation.
    expect: []const u8 = "",
    /// Why the appliance -- or the build, or the harness -- needs it.
    why: []const u8,

    pub fn required(self: Requirement) bool {
        return self.audience == .guest_runtime;
    }
};

/// The core appliance's contract, sorted by `id` and duplicate-free so the
/// canonical serialization below is stable without sorting at run time.
///
/// Sorting is enforced by a test rather than by a comment: the digest that
/// binds this table into provenance is order-sensitive, and an entry inserted
/// in the wrong place would change the digest without changing the contract.
pub const core_requirements = [_]Requirement{
    .{
        .id = "admin-home",
        .kind = .directory,
        .target = "/home",
        .behavior = .admin_privilege,
        .why = "azagent creates the provisioned administrator's home under it",
    },
    .{
        .id = "admin-shell",
        .kind = .command,
        .target = "/usr/bin/bash",
        .behavior = .admin_privilege,
        .why = "the provisioned account's login shell, and the shell mizinit " ++
            "execs for the console diagnostic session",
    },
    .{
        .id = "azagent",
        .kind = .command,
        .target = "/usr/sbin/azagent",
        .behavior = .azure_provisioning,
        .why = "Azure provisioning and WireServer readiness reporting",
    },
    .{
        .id = "azagent-config",
        .kind = .config,
        .target = "/etc/waagent.conf",
        .behavior = .storage_policy,
        .expect = "ResourceDisk.Format=y",
        .why = "resource-disk formatting and managed data disk policy azagent reads",
    },
    .{
        .id = "azagent-state",
        .kind = .mutable_path,
        .target = "/var/lib/azagent",
        .behavior = .azure_provisioning,
        .presence = .runtime,
        .why = "the provisioning sentinel mizinit gates SSH on",
    },
    .{
        .id = "binder-control-device",
        .kind = .device,
        .target = "/dev/binderfs/binder-control",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "dynamic Binder device allocation, the property that makes " ++
            "binderfs more than a fixed device count",
    },
    .{
        .id = "binder-device",
        .kind = .device,
        .target = "/dev/binderfs/binder",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "the default Binder IPC domain",
    },
    .{
        .id = "binder-hwbinder-device",
        .kind = .device,
        .target = "/dev/binderfs/hwbinder",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "the hardware Binder IPC domain",
    },
    .{
        .id = "binder-module",
        .kind = .kernel_module,
        .target = "binder_linux",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "loaded from the signed in-tree module set at boot and required " ++
            "to be untainted, which is what proves signature enforcement held",
    },
    .{
        .id = "binder-vndbinder-device",
        .kind = .device,
        .target = "/dev/binderfs/vndbinder",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "the vendor Binder IPC domain",
    },
    .{
        .id = "binderfs-mount",
        .kind = .mount,
        .target = "/dev/binderfs",
        .behavior = .binder_workload,
        .presence = .runtime,
        .expect = "binder",
        .why = "mizinit mounts binderfs before any access provider starts",
    },
    .{
        .id = "boot-directory",
        .kind = .directory,
        .target = "/boot",
        .behavior = .platform_trust,
        .why = "the kernel image and generated initramfs the signed UKI is built from",
    },
    .{
        .id = "ca-certificates-bundle",
        .kind = .trust_store,
        .target = "/etc/ssl/certs/ca-certificates.crt",
        .behavior = .trust_store,
        .expect = "-----BEGIN CERTIFICATE-----",
        .why = "the trust store #677 requires to remain present and valid; " ++
            "an empty or marker-less bundle is a broken trust store, not a small one",
    },
    .{
        .id = "ca-certificates-directory",
        .kind = .directory,
        .target = "/etc/ssl/certs",
        .behavior = .trust_store,
        .why = "the hashed-certificate directory OpenSSL clients walk",
    },
    .{
        .id = "ca-certificates-package",
        .kind = .package,
        .target = "ca-certificates",
        .behavior = .trust_store,
        .why = "an explicit package root #677 keeps by name",
    },
    .{
        .id = "core-provenance",
        .kind = .file,
        .target = "/var/lib/miz/ubuntu2604-core-provenance.json",
        .behavior = .provenance,
        .why = "the in-image record binding the running appliance to its build",
    },
    .{
        .id = "device-mount",
        .kind = .mount,
        .target = "/dev",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .expect = "devtmpfs",
        .why = "mizinit mounts it before anything can open a device node",
    },
    .{
        .id = "dma-heap-system",
        .kind = .device,
        .target = "/dev/dma_heap/system",
        .behavior = .binder_workload,
        .presence = .runtime,
        .why = "the built-in system DMA heap the Binder workload allocates from",
    },
    .{
        .id = "dmesg",
        .kind = .command,
        .target = "/usr/bin/dmesg",
        .behavior = .diagnostics,
        .why = "the kernel ring buffer is the only first-line evidence a " ++
            "headless appliance can offer for a failed boot, module rejection, " ++
            "or lockdown refusal",
    },
    .{
        .id = "harness-base64",
        .kind = .command,
        .target = "/usr/bin/base64",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "how acceptance uploads a static probe over an SSH session; " ++
            "the appliance itself never decodes base64",
    },
    .{
        .id = "harness-findmnt",
        .kind = .command,
        .target = "/usr/bin/findmnt",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "superseded by the static probe's own /proc/mounts reader; " ++
            "retained here only so its disappearance is attributed, not mourned",
    },
    .{
        .id = "harness-modinfo",
        .kind = .command,
        .target = "/usr/sbin/modinfo",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "acceptance-only module introspection; mizinit loads modules " ++
            "with finit_module and never shells out",
    },
    .{
        .id = "harness-modprobe",
        .kind = .command,
        .target = "/usr/sbin/modprobe",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "only acceptance modprobes spare modules to prove signature " ++
            "enforcement; the appliance uses finit_module",
    },
    .{
        .id = "harness-od",
        .kind = .command,
        .target = "/usr/bin/od",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "superseded by the static probe's own efivar reader",
    },
    .{
        .id = "harness-sha256sum",
        .kind = .command,
        .target = "/usr/bin/sha256sum",
        .behavior = .diagnostics,
        .audience = .acceptance_only,
        .why = "how acceptance confirms an uploaded probe arrived intact",
    },
    .{
        .id = "initramfs-tools-package",
        .kind = .package,
        .target = "initramfs-tools",
        .behavior = .platform_trust,
        .audience = .build_tooling,
        .why = "generates the initramfs the UKI embeds; #677 step 4 resolves " ++
            "it as a root of the initramfs build stage only, so neither it nor " ++
            "its build-only closure is installed into the final guest",
    },
    .{
        .id = "kernel-lockdown",
        .kind = .kernel_lockdown,
        .target = "/sys/kernel/security/lockdown",
        .behavior = .platform_trust,
        .presence = .runtime,
        .why = "integrity or confidentiality lockdown is what makes signed " ++
            "module loading enforceable rather than advisory",
    },
    .{
        .id = "kernel-selection",
        .kind = .package_selector,
        .target = "linux-azure",
        .behavior = .platform_trust,
        .expect = "linux-image-*-azure,linux-modules-*-azure",
        .why = "the signed kernel, its signed module tree, and the Azure " ++
            "storage and network drivers the appliance boots on; the " ++
            "metapackage is resolved to learn which kernel release Canonical " ++
            "currently ships and is then not installed, because its own " ++
            "dependencies are headers, perf tools, cloud tools, and a ZFS " ++
            "module set no appliance behavior stands on",
    },
    .{
        .id = "machine-id",
        .kind = .file,
        .target = "/etc/machine-id",
        .behavior = .provenance,
        .why = "shipped empty so the generalized image acquires identity at " ++
            "first boot instead of carrying one",
    },
    .{
        .id = "mizinit",
        .kind = .command,
        .target = "/usr/sbin/mizinit",
        .behavior = .pid1_lifecycle,
        .why = "PID 1",
    },
    .{
        .id = "mizinit-init-link",
        .kind = .symlink,
        .target = "/usr/sbin/init",
        .behavior = .pid1_lifecycle,
        .expect = "mizinit",
        .why = "the name the kernel looks for when no init= is supplied",
    },
    .{
        .id = "mizinit-log",
        .kind = .file,
        .target = "/run/mizinit.log",
        .behavior = .diagnostics,
        .presence = .runtime,
        .why = "PID 1's own record of supervision decisions, which is the only " ++
            "explanation available when SSH never opens",
    },
    .{
        .id = "mizinit-pid1",
        .kind = .pid1,
        .target = "/usr/sbin/mizinit",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .why = "the appliance runs no service manager; PID 1 is mizinit itself",
    },
    .{
        .id = "mizinit-poweroff-link",
        .kind = .symlink,
        .target = "/usr/sbin/poweroff",
        .behavior = .pid1_lifecycle,
        .expect = "mizinit",
        .why = "the shutdown path an operator or the platform invokes",
    },
    .{
        .id = "mizinit-reboot-link",
        .kind = .symlink,
        .target = "/usr/sbin/reboot",
        .behavior = .pid1_lifecycle,
        .expect = "mizinit",
        .why = "the reboot path acceptance exercises and the platform invokes",
    },
    .{
        .id = "mizinit-runtime-dir",
        .kind = .mutable_path,
        .target = "/run/mizinit",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .why = "where PID 1 stages provisioning media before azagent reads it",
    },
    .{
        .id = "mizinit-shutdown-link",
        .kind = .symlink,
        .target = "/usr/sbin/shutdown",
        .behavior = .pid1_lifecycle,
        .expect = "mizinit",
        .why = "the orderly shutdown entry point",
    },
    .{
        .id = "module-tree",
        .kind = .directory,
        .target = "/usr/lib/modules",
        .behavior = .platform_trust,
        .why = "the signed module tree finit_module loads binder_linux from",
    },
    .{
        .id = "openssh-server-package",
        .kind = .package,
        .target = "openssh-server",
        .behavior = .ssh_key_only,
        .why = "the only access path the appliance offers",
    },
    .{
        .id = "package-lock",
        .kind = .file,
        .target = "/var/lib/miz/ubuntu2604-package-lock.tsv",
        .behavior = .provenance,
        .why = "the exact closure the image shipped, readable from the image itself",
    },
    .{
        .id = "proc-mount",
        .kind = .mount,
        .target = "/proc",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .expect = "proc",
        .why = "mizinit reads the kernel command line and supervises children through it",
    },
    .{
        .id = "root-mount",
        .kind = .mount,
        .target = "/",
        .behavior = .storage_policy,
        .presence = .runtime,
        .expect = "ext4",
        .why = "the root filesystem azagent grows to fill the provisioned disk",
    },
    .{
        .id = "run-mount",
        .kind = .mount,
        .target = "/run",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .expect = "tmpfs",
        .why = "the volatile state directory PID 1 and sshd both require",
    },
    .{
        .id = "secure-boot",
        .kind = .secure_boot,
        .target = "/sys/firmware/efi/efivars",
        .behavior = .platform_trust,
        .presence = .runtime,
        .why = "firmware must report Secure Boot enabled, which is what makes " ++
            "the signed UKI and signed modules meaningful",
    },
    .{
        .id = "source-release",
        .kind = .file,
        .target = "/var/lib/miz/source-release",
        .behavior = .provenance,
        .why = "the Canonical snapshot the image was built from",
    },
    .{
        .id = "ssh-host-key",
        .kind = .file,
        .target = "/etc/ssh/ssh_host_ed25519_key",
        .behavior = .ssh_key_only,
        .presence = .runtime,
        .why = "generated at first boot; a baked host key would make every " ++
            "instance of the image the same host",
    },
    .{
        .id = "ssh-keygen",
        .kind = .command,
        .target = "/usr/bin/ssh-keygen",
        .behavior = .ssh_key_only,
        .why = "first-boot host-key generation",
    },
    .{
        .id = "sshd",
        .kind = .command,
        .target = "/usr/sbin/sshd",
        .behavior = .ssh_key_only,
        .why = "the access provider mizinit supervises directly",
    },
    .{
        .id = "sshd-policy",
        .kind = .config,
        .target = "/etc/ssh/sshd_config.d/10-mizinit.conf",
        .behavior = .ssh_key_only,
        .expect = "PasswordAuthentication no",
        .why = "the drop-in that makes access key-only rather than key-preferred",
    },
    .{
        .id = "sshd-runtime-dir",
        .kind = .mutable_path,
        .target = "/run/sshd",
        .behavior = .ssh_key_only,
        .presence = .runtime,
        .why = "sshd's privilege-separation directory, created by PID 1 before it starts",
    },
    .{
        .id = "sudo",
        .kind = .command,
        .target = "/usr/bin/sudo",
        .behavior = .admin_privilege,
        .why = "the passwordless privilege path the provisioned administrator uses",
    },
    .{
        .id = "sudo-package",
        .kind = .package,
        .target = "sudo",
        .behavior = .admin_privilege,
        .why = "an explicit package root; the appliance provisions no password, " ++
            "so this is the only privilege escalation path",
    },
    .{
        .id = "sudoers-dropin",
        .kind = .config,
        .target = "/etc/sudoers.d/azagent",
        .behavior = .admin_privilege,
        .presence = .runtime,
        .expect = "NOPASSWD",
        .why = "written by azagent at provisioning; without it the administrator " ++
            "account has no way to reach root",
    },
    .{
        .id = "sys-mount",
        .kind = .mount,
        .target = "/sys",
        .behavior = .pid1_lifecycle,
        .presence = .runtime,
        .expect = "sysfs",
        .why = "device, module, and firmware state mizinit and azagent both read",
    },
    .{
        .id = "tpm-device",
        .kind = .device,
        .target = "/dev/tpm0",
        .behavior = .platform_trust,
        .presence = .runtime,
        .why = "the vTPM a Trusted Launch VM is required to expose",
    },
    .{
        .id = "tpmrm-device",
        .kind = .device,
        .target = "/dev/tpmrm0",
        .behavior = .platform_trust,
        .presence = .runtime,
        .why = "the resource-managed vTPM interface applications use",
    },
};

pub fn requirements() []const Requirement {
    return &core_requirements;
}

pub fn lookup(id: []const u8) ?Requirement {
    for (core_requirements) |entry| {
        if (std.mem.eql(u8, entry.id, id)) return entry;
    }
    return null;
}

/// Number of entries an audience owns, so callers can report the split without
/// re-deriving it.
pub fn countFor(audience: Audience) usize {
    var total: usize = 0;
    for (core_requirements) |entry| {
        if (entry.audience == audience) total += 1;
    }
    return total;
}

/// The explicit debz package roots the contract's `package` entries name, in
/// contract (`id`) order.
///
/// Step 3 of #677 replaced the `ubuntu-minimal` metapackage with exactly this
/// set. Derived rather than written down twice, because the whole point of the
/// exercise is that a package root exists if and only if a named behavior
/// stands on it: a root nothing in this table asks for is a convenience, and a
/// contract package that is not a root is an unenforced promise.
///
/// This is every root the *build* resolves, across both audiences. Step 4 of
/// #677 splits where they are resolved -- see `guest_package_roots` and
/// `build_package_roots` -- so this list is no longer the list of packages the
/// final guest carries, and callers that mean the guest must say so.
pub const package_roots: [countKind(.package)][]const u8 = blk: {
    var names: [countKind(.package)][]const u8 = undefined;
    var next: usize = 0;
    for (core_requirements) |entry| {
        if (entry.kind != .package) continue;
        names[next] = entry.target;
        next += 1;
    }
    break :blk names;
};

/// Number of `package` entries an audience owns, at comptime.
pub fn countPackagesFor(comptime audience: Audience) usize {
    var total: usize = 0;
    for (core_requirements) |entry| {
        if (entry.kind == .package and entry.audience == audience) total += 1;
    }
    return total;
}

/// The literal package roots installed into the final guest, in contract order.
///
/// The kernel is not here: it is selected rather than named, so
/// `kernel_selector` describes it and `selectKernel` produces the two versioned
/// roots the guest actually installs.
pub const guest_package_roots: [countPackagesFor(.guest_runtime)][]const u8 = blk: {
    var names: [countPackagesFor(.guest_runtime)][]const u8 = undefined;
    var next: usize = 0;
    for (core_requirements) |entry| {
        if (entry.kind != .package or entry.audience != .guest_runtime) continue;
        names[next] = entry.target;
        next += 1;
    }
    break :blk names;
};

/// The package roots resolved only into the initramfs build stage.
///
/// Issue #677 step 4: these are installed into a staging root that produces the
/// initramfs and is then discarded. A build root that turns up in the final
/// guest inventory is a build/runtime separation failure, which is why
/// `forbidden_packages` names every one of them.
pub const build_package_roots: [countPackagesFor(.build_tooling)][]const u8 = blk: {
    var names: [countPackagesFor(.build_tooling)][]const u8 = undefined;
    var next: usize = 0;
    for (core_requirements) |entry| {
        if (entry.kind != .package or entry.audience != .build_tooling) continue;
        names[next] = entry.target;
        next += 1;
    }
    break :blk names;
};

/// Number of entries of a kind, evaluated at comptime so the derived tables
/// above can size themselves.
pub fn countKind(comptime kind: Kind) usize {
    var total: usize = 0;
    for (core_requirements) |entry| {
        if (entry.kind == kind) total += 1;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Kernel selection (issue #677 step 4).
// ---------------------------------------------------------------------------

/// The name templates a kernel selection must produce, `*` standing for the
/// kernel release the selector resolved to.
pub const KernelTemplates = struct {
    /// The metapackage that is resolved and then not installed.
    selector: []const u8,
    image: []const u8,
    modules: []const u8,
};

/// The contract's single `package_selector` entry, decoded.
pub const kernel_templates: KernelTemplates = blk: {
    var found: ?KernelTemplates = null;
    for (core_requirements) |entry| {
        if (entry.kind != .package_selector) continue;
        if (found != null) @compileError("the contract names more than one package selector");
        const comma = std.mem.indexOfScalar(u8, entry.expect, ',') orelse
            @compileError("a package selector must name an image and a modules template");
        found = .{
            .selector = entry.target,
            .image = entry.expect[0..comma],
            .modules = entry.expect[comma + 1 ..],
        };
    }
    break :blk found orelse @compileError("the contract names no package selector");
};

/// The kernel release a `prefix*suffix` template matches in `name`, or null.
///
/// The release is everything after the prefix -- `linux-image-*-azure` matched
/// against `linux-image-7.0.0-1010-azure` yields `7.0.0-1010-azure`, which is
/// the release name `/boot/vmlinuz-*`, `/usr/lib/modules/*`, and the module
/// signature checks all use, so no caller has to reassemble it. A release is
/// never empty, so `linux-image-azure` is not a selection: the metapackage
/// cannot pass for the versioned package it depends on.
pub fn templateRelease(template: []const u8, name: []const u8) ?[]const u8 {
    const star = std.mem.indexOfScalar(u8, template, '*') orelse return null;
    const prefix = template[0..star];
    const suffix = template[star + 1 ..];
    if (name.len <= prefix.len + suffix.len) return null;
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    const release = name[prefix.len..];
    for (release) |byte| switch (byte) {
        '0'...'9', 'a'...'z', 'A'...'Z', '.', '+', '~', '-', '_' => {},
        else => return null,
    };
    return release;
}

/// The package name a template takes for `release`, written into `buffer`.
pub fn templateName(
    buffer: []u8,
    template: []const u8,
    release: []const u8,
) error{NoSpaceLeft}![]const u8 {
    const star = std.mem.indexOfScalar(u8, template, '*') orelse return error.NoSpaceLeft;
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ template[0..star], release });
}

/// The versioned kernel roots a selection resolved to.
pub const KernelSelection = struct {
    /// The kernel release, e.g. `7.0.0-1010-azure`. It is also the name of the
    /// module tree the UKI's initramfs and the signed module loader use.
    release: []const u8,
    image_package: []const u8,
    modules_package: []const u8,
};

pub const SelectKernelError = error{
    /// No candidate matched the image template.
    KernelImageNotSelected,
    /// More than one release matched, so "the kernel" is ambiguous.
    KernelSelectionAmbiguous,
    /// The image was selected but its module tree was not published with it.
    KernelModulesNotSelected,
};

/// Accumulates candidate names into a single kernel selection.
///
/// Fail-closed by construction: zero matches, two different releases, or an
/// image whose module tree was not published with it are all errors, because
/// each of them would otherwise be answered by silently installing something
/// else. Names are borrowed, so a caller may feed it slices of a lock or an
/// inventory without allocating.
pub const KernelSelector = struct {
    image_release: ?[]const u8 = null,
    image_package: ?[]const u8 = null,
    modules_release: ?[]const u8 = null,
    modules_package: ?[]const u8 = null,

    pub fn offer(self: *KernelSelector, name: []const u8) SelectKernelError!void {
        if (templateRelease(kernel_templates.image, name)) |release| {
            if (self.image_release) |chosen| {
                if (!std.mem.eql(u8, chosen, release)) return error.KernelSelectionAmbiguous;
            } else {
                self.image_release = release;
                self.image_package = name;
            }
        }
        if (templateRelease(kernel_templates.modules, name)) |release| {
            if (self.modules_release) |chosen| {
                if (!std.mem.eql(u8, chosen, release)) return error.KernelSelectionAmbiguous;
            } else {
                self.modules_release = release;
                self.modules_package = name;
            }
        }
    }

    pub fn finish(self: KernelSelector) SelectKernelError!KernelSelection {
        const release = self.image_release orelse return error.KernelImageNotSelected;
        const modules = self.modules_release orelse return error.KernelModulesNotSelected;
        if (!std.mem.eql(u8, release, modules)) return error.KernelModulesNotSelected;
        return .{
            .release = release,
            .image_package = self.image_package.?,
            .modules_package = self.modules_package.?,
        };
    }
};

/// Picks the versioned kernel roots out of the names a selector lock resolved.
pub fn selectKernel(names: []const []const u8) SelectKernelError!KernelSelection {
    var selector: KernelSelector = .{};
    for (names) |name| try selector.offer(name);
    return selector.finish();
}

pub fn isPackageRoot(name: []const u8) bool {
    for (package_roots) |root| {
        if (std.mem.eql(u8, root, name)) return true;
    }
    return false;
}

pub fn isGuestPackageRoot(name: []const u8) bool {
    for (guest_package_roots) |root| {
        if (std.mem.eql(u8, root, name)) return true;
    }
    return false;
}

pub fn isBuildPackageRoot(name: []const u8) bool {
    for (build_package_roots) |root| {
        if (std.mem.eql(u8, root, name)) return true;
    }
    return false;
}

fn isSameSet(names: []const []const u8, expected: []const []const u8) bool {
    if (names.len != expected.len) return false;
    for (expected) |root| {
        var found = false;
        for (names) |name| {
            if (std.mem.eql(u8, root, name)) {
                if (found) return false;
                found = true;
            }
        }
        if (!found) return false;
    }
    return true;
}

/// Whether `names` is the contract's package-root set, ignoring order.
///
/// Order is a build decision -- the kernel is resolved first because its
/// transaction is the one that creates the otherwise-empty baseline -- so
/// callers keep their own deliberate ordering and use this to prove they kept
/// the same members.
pub fn isPackageRootSet(names: []const []const u8) bool {
    return isSameSet(names, &package_roots);
}

/// Whether `names` is exactly the literal guest roots, ignoring order. The
/// selected kernel roots are not literals and are checked by `selectKernel`.
pub fn isGuestPackageRootSet(names: []const []const u8) bool {
    return isSameSet(names, &guest_package_roots);
}

/// Whether `names` is exactly the build-stage roots, ignoring order.
pub fn isBuildPackageRootSet(names: []const []const u8) bool {
    return isSameSet(names, &build_package_roots);
}

/// Packages the core closure must never contain.
///
/// The exact-closure equality check is what actually keeps the inventory
/// honest -- an unexpected package fails whether or not it is named here.
/// This list exists so the regressions #677 calls out by name fail with the
/// name of what came back: a broad metapackage, an apt client, an editor, a
/// pager, locales, documentation, a conventional networking daemon, an init
/// system, a convenience tool, or -- since step 4 -- the initramfs generator
/// and the kernel convenience metapackages that only the build needs. Every
/// entry is a package no `guest_runtime` behavior stands on, which the test
/// below re-checks against `guest_package_roots`.
pub const forbidden_packages = [_][]const u8{
    "apt",
    "busybox-initramfs",
    "cloud-init",
    "dhcpcd-base",
    "dracut-install",
    "initramfs-tools",
    "initramfs-tools-bin",
    "initramfs-tools-core",
    "isc-dhcp-client",
    "klibc-utils",
    "linux-azure",
    "linux-cloud-tools-azure",
    "linux-headers-azure",
    "linux-image-azure",
    "linux-tools-azure",
    "locales",
    "man-db",
    "nano",
    "netplan.io",
    "network-manager",
    "snapd",
    "systemd",
    "systemd-sysv",
    "ubuntu-minimal",
    "ubuntu-server",
    "ubuntu-server-minimal",
    "ubuntu-standard",
    "udev",
    "unattended-upgrades",
    "vim-tiny",
    "walinuxagent",
};

pub fn isForbiddenPackage(name: []const u8) bool {
    for (forbidden_packages) |forbidden| {
        if (std.mem.eql(u8, forbidden, name)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Canonical serialization and digest.
// ---------------------------------------------------------------------------

/// One canonical tab-separated line per requirement, then one per forbidden
/// package, terminated by newlines.
///
/// The digest over these lines is what binds a shipped image to the contract
/// it was built against. It covers every field that changes meaning, so a
/// reclassified audience, a relaxed expectation, or a convenience quietly
/// dropped from the forbidden set moves the digest even when the entry count
/// does not.
pub fn writeCanonical(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    for (core_requirements) |entry| {
        try writer.print("{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            entry.id,
            entry.kind.key(),
            entry.target,
            entry.behavior.key(),
            entry.audience.key(),
            entry.presence.key(),
            entry.expect,
        });
    }
    for (forbidden_packages) |name| {
        try writer.print("{s}\t{s}\n", .{ forbidden_canonical_prefix, name });
    }
}

/// The first field of a forbidden-package line. It is not a legal requirement
/// `id` -- ids never contain a space -- so no requirement line can be mistaken
/// for one, or the reverse.
pub const forbidden_canonical_prefix = "forbidden package";

pub const digest_hex_len = 64;

/// Lowercase hex SHA-256 over the canonical serialization.
pub fn digest() [digest_hex_len]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    for (core_requirements) |entry| {
        writer.end = 0;
        writer.print("{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            entry.id,
            entry.kind.key(),
            entry.target,
            entry.behavior.key(),
            entry.audience.key(),
            entry.presence.key(),
            entry.expect,
        }) catch unreachable;
        hasher.update(writer.buffered());
    }
    for (forbidden_packages) |name| {
        writer.end = 0;
        writer.print("{s}\t{s}\n", .{ forbidden_canonical_prefix, name }) catch unreachable;
        hasher.update(writer.buffered());
    }
    var raw: [32]u8 = undefined;
    hasher.final(&raw);
    var hex: [digest_hex_len]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&raw}) catch unreachable;
    return hex;
}

// ---------------------------------------------------------------------------
// Probe report shape.
//
// The guest probe prints one line per evaluated requirement. Both the probe
// and every consumer use the constructors and parser below, so the wire format
// has exactly one definition and a typo cannot make a failure look like a pass.
// ---------------------------------------------------------------------------

pub const Status = enum {
    ok,
    missing,
    wrong_type,
    not_executable,
    not_readable,
    not_writable,
    not_mounted,
    wrong_filesystem,
    wrong_target,
    marker_absent,
    tainted,
    disabled,
    unreadable,

    pub fn key(self: Status) []const u8 {
        return switch (self) {
            .ok => "ok",
            .missing => "missing",
            .wrong_type => "wrong-type",
            .not_executable => "not-executable",
            .not_readable => "not-readable",
            .not_writable => "not-writable",
            .not_mounted => "not-mounted",
            .wrong_filesystem => "wrong-filesystem",
            .wrong_target => "wrong-target",
            .marker_absent => "marker-absent",
            .tainted => "tainted",
            .disabled => "disabled",
            .unreadable => "unreadable",
        };
    }

    pub fn parse(text: []const u8) ?Status {
        inline for (@typeInfo(Status).@"enum".fields) |info| {
            const candidate: Status = @enumFromInt(info.value);
            if (std.mem.eql(u8, text, candidate.key())) return candidate;
        }
        return null;
    }
};

pub const report_prefix = "runtime-contract";
pub const filesystem_prefix = "filesystem";

pub const ReportLine = struct {
    id: []const u8,
    status: Status,
};

/// Parses one `runtime-contract id=<id> status=<status> ...` line.
///
/// Allocation-free and total, so every rejection shape is unit-testable
/// without a guest.
pub fn parseReportLine(line: []const u8) error{Unparseable}!ReportLine {
    var rest = line;
    if (!std.mem.startsWith(u8, rest, report_prefix ++ " ")) return error.Unparseable;
    rest = rest[report_prefix.len + 1 ..];
    const id = try namedField(rest, "id=") orelse return error.Unparseable;
    const status_text = try namedField(rest, "status=") orelse return error.Unparseable;
    if (id.len == 0) return error.Unparseable;
    const status = Status.parse(status_text) orelse return error.Unparseable;
    return .{ .id = id, .status = status };
}

/// Finds ` name=value` (or a leading `name=value`) and returns the value up to
/// the next space. Returns null when the field is absent.
fn namedField(text: []const u8, name: []const u8) error{Unparseable}!?[]const u8 {
    var offset: usize = 0;
    while (offset < text.len) {
        const at_start = offset == 0 or text[offset - 1] == ' ';
        if (at_start and std.mem.startsWith(u8, text[offset..], name)) {
            const value_start = offset + name.len;
            const end = std.mem.indexOfScalarPos(u8, text, value_start, ' ') orelse text.len;
            return text[value_start..end];
        }
        offset += 1;
    }
    return null;
}

/// ext4 accounting the probe reports for one path, in the exact shape
/// `size_inventory.FilesystemUsage` expects.
pub const FilesystemLine = struct {
    path: []const u8,
    block_size: u64,
    total_blocks: u64,
    free_blocks: u64,
    total_inodes: u64,
    free_inodes: u64,
};

pub fn parseFilesystemLine(line: []const u8) error{Unparseable}!FilesystemLine {
    if (!std.mem.startsWith(u8, line, filesystem_prefix ++ " ")) return error.Unparseable;
    const rest = line[filesystem_prefix.len + 1 ..];
    const path = try namedField(rest, "path=") orelse return error.Unparseable;
    if (path.len == 0) return error.Unparseable;
    return .{
        .path = path,
        .block_size = try countField(rest, "block_size="),
        .total_blocks = try countField(rest, "total_blocks="),
        .free_blocks = try countField(rest, "free_blocks="),
        .total_inodes = try countField(rest, "total_inodes="),
        .free_inodes = try countField(rest, "free_inodes="),
    };
}

fn countField(text: []const u8, name: []const u8) error{Unparseable}!u64 {
    const value = try namedField(text, name) orelse return error.Unparseable;
    return std.fmt.parseInt(u64, value, 10) catch error.Unparseable;
}

/// Why a probe report was refused, with enough detail for one operator-facing
/// line naming the offending requirement.
pub const Reason = enum {
    unparseable_line,
    unknown_id,
    duplicate_id,
    not_reported,
    not_satisfied,
};

pub const Rejection = struct {
    reason: Reason,
    id: []const u8,
    status: ?Status = null,
};

/// Confirms `output` reports every probeable requirement exactly once and that
/// every `guest_runtime` requirement reported `ok`.
///
/// `acceptance_only` entries must still be *reported* -- a report that silently
/// stopped evaluating them would hide a probe that had quietly become partial
/// -- but they are allowed to be missing from the guest, because nothing in the
/// image may be retained solely for a test.
///
/// `seen` must have room for one flag per requirement; passing it in keeps this
/// function allocation-free so the guest-side and host-side callers can share it.
pub fn verifyReport(
    output: []const u8,
    seen: *[core_requirements.len]bool,
) ?Rejection {
    @memset(seen, false);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, report_prefix ++ " ")) continue;
        const parsed = parseReportLine(line) catch return .{
            .reason = .unparseable_line,
            .id = "",
        };
        const index = indexOf(parsed.id) orelse return .{
            .reason = .unknown_id,
            .id = parsed.id,
        };
        if (seen[index]) return .{ .reason = .duplicate_id, .id = parsed.id };
        seen[index] = true;
        const entry = core_requirements[index];
        if (entry.required() and parsed.status != .ok) return .{
            .reason = .not_satisfied,
            .id = entry.id,
            .status = parsed.status,
        };
    }
    for (core_requirements, 0..) |entry, index| {
        if (!entry.kind.probeable()) continue;
        if (!seen[index]) return .{ .reason = .not_reported, .id = entry.id };
    }
    return null;
}

/// The status a report recorded for `id`, or null when it never mentioned it.
///
/// Callers that own one named contract -- "is BinderFS mounted", "is the DMA
/// heap usable" -- ask this instead of re-running a second shell check, so a
/// single probe run answers every contract that depends on it.
pub fn statusOf(output: []const u8, id: []const u8) ?Status {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, report_prefix ++ " ")) continue;
        const parsed = parseReportLine(line) catch continue;
        if (std.mem.eql(u8, parsed.id, id)) return parsed.status;
    }
    return null;
}

fn indexOf(id: []const u8) ?usize {
    for (core_requirements, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.id, id)) return index;
    }
    return null;
}

/// One operator-facing sentence for a rejection.
pub fn describe(rejection: Rejection, buffer: []u8) []const u8 {
    return switch (rejection.reason) {
        .unparseable_line => std.fmt.bufPrint(
            buffer,
            "runtime contract probe emitted an unparseable line",
            .{},
        ),
        .unknown_id => std.fmt.bufPrint(
            buffer,
            "runtime contract probe reported unknown requirement {s}",
            .{rejection.id},
        ),
        .duplicate_id => std.fmt.bufPrint(
            buffer,
            "runtime contract probe reported requirement {s} twice",
            .{rejection.id},
        ),
        .not_reported => std.fmt.bufPrint(
            buffer,
            "runtime contract probe did not report requirement {s}",
            .{rejection.id},
        ),
        .not_satisfied => std.fmt.bufPrint(
            buffer,
            "runtime contract requirement {s} ({s}) is {s}",
            .{
                rejection.id,
                lookup(rejection.id).?.target,
                if (rejection.status) |status| status.key() else "unsatisfied",
            },
        ),
    } catch "runtime contract probe report was refused";
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

test "requirements are sorted, unique, and fully attributed" {
    var index: usize = 1;
    while (index < core_requirements.len) : (index += 1) {
        try std.testing.expect(std.mem.lessThan(
            u8,
            core_requirements[index - 1].id,
            core_requirements[index].id,
        ));
    }
    for (core_requirements) |entry| {
        try std.testing.expect(entry.id.len != 0);
        try std.testing.expect(entry.target.len != 0);
        try std.testing.expect(entry.why.len != 0);
        switch (entry.kind) {
            .mount, .symlink, .config, .trust_store, .package_selector => try std.testing.expect(entry.expect.len != 0),
            else => {},
        }
        if (entry.kind == .package or entry.kind == .package_selector) {
            try std.testing.expectEqual(Presence.image, entry.presence);
        }
    }
}

test "every behavior named by issue 677 has at least one guest requirement" {
    inline for (@typeInfo(Behavior).@"enum".fields) |field_info| {
        const behavior: Behavior = @enumFromInt(field_info.value);
        var found = false;
        for (core_requirements) |entry| {
            if (entry.behavior == behavior and entry.required()) found = true;
        }
        try std.testing.expect(found);
    }
}

test "ca-certificates stays an explicit package root with a validated trust store" {
    const package = lookup("ca-certificates-package").?;
    try std.testing.expectEqual(Kind.package, package.kind);
    try std.testing.expectEqual(Audience.guest_runtime, package.audience);
    const bundle = lookup("ca-certificates-bundle").?;
    try std.testing.expectEqual(Kind.trust_store, bundle.kind);
    try std.testing.expectEqualStrings("-----BEGIN CERTIFICATE-----", bundle.expect);
    try std.testing.expect(bundle.required());
}

test "the derived package roots split guest runtime from build tooling" {
    // #677 step 3 replaced `ubuntu-minimal` with explicit roots; step 4 splits
    // those roots by audience so the build's generator never reaches the guest.
    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{
        "ca-certificates",
        "initramfs-tools",
        "openssh-server",
        "sudo",
    }, &package_roots);
    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{
        "ca-certificates",
        "openssh-server",
        "sudo",
    }, &guest_package_roots);
    try std.testing.expectEqualSlices(
        []const u8,
        &[_][]const u8{"initramfs-tools"},
        &build_package_roots,
    );
    try std.testing.expect(isPackageRoot("ca-certificates"));
    try std.testing.expect(!isPackageRoot("ubuntu-minimal"));
    // The kernel is selected, not named, so it is deliberately not a root.
    try std.testing.expect(!isPackageRoot("linux-azure"));
    try std.testing.expect(isGuestPackageRoot("ca-certificates"));
    try std.testing.expect(!isGuestPackageRoot("initramfs-tools"));
    try std.testing.expect(isBuildPackageRoot("initramfs-tools"));
    try std.testing.expect(!isBuildPackageRoot("ca-certificates"));
    for (core_requirements) |entry| {
        try std.testing.expectEqual(entry.kind == .package, isPackageRoot(entry.target));
    }
    // The build orders its roots deliberately; only the membership is derived.
    try std.testing.expect(isPackageRootSet(&.{
        "initramfs-tools",
        "openssh-server",
        "sudo",
        "ca-certificates",
    }));
    try std.testing.expect(!isPackageRootSet(&.{
        "ubuntu-minimal",
        "initramfs-tools",
        "openssh-server",
        "sudo",
        "ca-certificates",
    }));
    try std.testing.expect(!isPackageRootSet(&.{
        "initramfs-tools",
        "openssh-server",
        "sudo",
    }));
    // A duplicated member must not pass for the missing one it displaced.
    try std.testing.expect(!isPackageRootSet(&.{
        "initramfs-tools",
        "initramfs-tools",
        "openssh-server",
        "sudo",
    }));
    try std.testing.expect(isGuestPackageRootSet(&.{ "openssh-server", "sudo", "ca-certificates" }));
    try std.testing.expect(!isGuestPackageRootSet(&.{
        "openssh-server",
        "sudo",
        "ca-certificates",
        "initramfs-tools",
    }));
    try std.testing.expect(isBuildPackageRootSet(&.{"initramfs-tools"}));
    try std.testing.expect(!isBuildPackageRootSet(&.{}));
}

test "the kernel is selected from a metapackage rather than pinned or installed" {
    // #677 step 4 wants exact versioned kernel packages *and* correct security
    // update selection. The selector is how both hold at once: the metapackage
    // decides which release, and only the two versioned binaries are installed.
    const entry = lookup("kernel-selection").?;
    try std.testing.expectEqual(Kind.package_selector, entry.kind);
    try std.testing.expectEqual(Audience.guest_runtime, entry.audience);
    try std.testing.expectEqualStrings("linux-azure", kernel_templates.selector);
    try std.testing.expectEqualStrings("linux-image-*-azure", kernel_templates.image);
    try std.testing.expectEqualStrings("linux-modules-*-azure", kernel_templates.modules);

    const resolved = try selectKernel(&.{
        "linux-azure",
        "linux-image-azure",
        "linux-image-7.0.0-1010-azure",
        "linux-modules-7.0.0-1010-azure",
        "openssh-server",
    });
    try std.testing.expectEqualStrings("7.0.0-1010-azure", resolved.release);
    try std.testing.expectEqualStrings("linux-image-7.0.0-1010-azure", resolved.image_package);
    try std.testing.expectEqualStrings("linux-modules-7.0.0-1010-azure", resolved.modules_package);

    // The metapackages themselves are not a selection: an empty release is not
    // a release, so `linux-image-azure` cannot stand in for a versioned image.
    try std.testing.expect(templateRelease(kernel_templates.image, "linux-image-azure") == null);
    try std.testing.expectError(
        error.KernelImageNotSelected,
        selectKernel(&.{ "linux-azure", "linux-image-azure" }),
    );
    try std.testing.expectError(error.KernelSelectionAmbiguous, selectKernel(&.{
        "linux-image-7.0.0-1010-azure",
        "linux-image-7.0.0-1004-azure",
    }));
    try std.testing.expectError(error.KernelModulesNotSelected, selectKernel(&.{
        "linux-image-7.0.0-1010-azure",
        "linux-modules-7.0.0-1004-azure",
    }));
}

test "no contract entry names a broad metapackage or a convenience tool" {
    // The acceptance criterion of #677 is that `ubuntu-minimal` is absent from
    // the final inventory, which starts with it being absent from the statement
    // of what the appliance needs.
    try std.testing.expect(isForbiddenPackage("ubuntu-minimal"));
    try std.testing.expect(!isForbiddenPackage("ca-certificates"));
    for (core_requirements) |entry| {
        if (entry.kind != .package or entry.audience != .guest_runtime) continue;
        try std.testing.expect(!isForbiddenPackage(entry.target));
    }
    // Step 4: the generator and the kernel conveniences are forbidden in the
    // guest precisely because the build still resolves them somewhere else.
    try std.testing.expect(isForbiddenPackage("initramfs-tools"));
    try std.testing.expect(isForbiddenPackage("linux-azure"));
    try std.testing.expect(isForbiddenPackage("linux-headers-azure"));
    for (build_package_roots) |name| try std.testing.expect(isForbiddenPackage(name));
    try std.testing.expect(isForbiddenPackage(kernel_templates.selector));
    for (forbidden_packages) |name| try std.testing.expect(!isGuestPackageRoot(name));
    var index: usize = 1;
    while (index < forbidden_packages.len) : (index += 1) {
        try std.testing.expect(std.mem.lessThan(
            u8,
            forbidden_packages[index - 1],
            forbidden_packages[index],
        ));
    }
}

test "acceptance-only conveniences are never guest requirements" {
    const harness = [_][]const u8{
        "harness-base64",
        "harness-findmnt",
        "harness-modinfo",
        "harness-modprobe",
        "harness-od",
        "harness-sha256sum",
    };
    for (harness) |id| {
        const entry = lookup(id).?;
        try std.testing.expectEqual(Audience.acceptance_only, entry.audience);
        try std.testing.expect(!entry.required());
    }
    try std.testing.expectEqual(harness.len, countFor(.acceptance_only));
    try std.testing.expectEqual(@as(usize, 1), countFor(.build_tooling));
}

test "the digest is stable and covers every field that changes meaning" {
    const first = digest();
    const second = digest();
    try std.testing.expectEqualStrings(&first, &second);
    try std.testing.expectEqual(@as(usize, digest_hex_len), first.len);
    for (first) |byte| try std.testing.expect(std.ascii.isHex(byte) and !std.ascii.isUpper(byte));
}

test "report lines round-trip through the parser" {
    const line = report_prefix ++ " id=mizinit kind=command status=ok target=/usr/sbin/mizinit";
    const parsed = try parseReportLine(line);
    try std.testing.expectEqualStrings("mizinit", parsed.id);
    try std.testing.expectEqual(Status.ok, parsed.status);

    const failed = report_prefix ++ " id=sudo kind=command status=not-executable target=/usr/bin/sudo";
    try std.testing.expectEqual(Status.not_executable, (try parseReportLine(failed)).status);
}

test "report line parsing rejects malformed input" {
    try std.testing.expectError(error.Unparseable, parseReportLine("garbage"));
    try std.testing.expectError(error.Unparseable, parseReportLine(report_prefix ++ " status=ok"));
    try std.testing.expectError(error.Unparseable, parseReportLine(report_prefix ++ " id=x"));
    try std.testing.expectError(
        error.Unparseable,
        parseReportLine(report_prefix ++ " id= status=ok"),
    );
    try std.testing.expectError(
        error.Unparseable,
        parseReportLine(report_prefix ++ " id=mizinit status=fine"),
    );
    // A field name that only appears mid-token must not be mistaken for the
    // field itself, or `grid=` would satisfy `id=`.
    try std.testing.expectError(
        error.Unparseable,
        parseReportLine(report_prefix ++ " grid=mizinit status=ok"),
    );
}

/// Builds a complete, passing report so failure tests can perturb exactly one
/// thing at a time.
fn completeReport(buffer: *std.Io.Writer.Allocating) !void {
    for (core_requirements) |entry| {
        if (!entry.kind.probeable()) continue;
        try buffer.writer.print("{s} id={s} kind={s} status=ok target={s}\n", .{
            report_prefix,
            entry.id,
            entry.kind.key(),
            entry.target,
        });
    }
}

test "a complete report is accepted and every failure shape is refused" {
    var seen: [core_requirements.len]bool = undefined;
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try completeReport(&buffer);
    const complete = buffer.written();
    try std.testing.expect(verifyReport(complete, &seen) == null);

    // Unknown identifier.
    var unknown: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer unknown.deinit();
    try unknown.writer.writeAll(complete);
    try unknown.writer.writeAll(report_prefix ++ " id=invented status=ok\n");
    try std.testing.expectEqual(Reason.unknown_id, verifyReport(unknown.written(), &seen).?.reason);

    // Duplicate identifier.
    var duplicate: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer duplicate.deinit();
    try duplicate.writer.writeAll(complete);
    try duplicate.writer.print("{s} id=mizinit status=ok\n", .{report_prefix});
    try std.testing.expectEqual(Reason.duplicate_id, verifyReport(duplicate.written(), &seen).?.reason);

    // Unparseable line.
    var broken: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer broken.deinit();
    try broken.writer.writeAll(complete);
    try broken.writer.print("{s} id= status=ok\n", .{report_prefix});
    try std.testing.expectEqual(Reason.unparseable_line, verifyReport(broken.written(), &seen).?.reason);
}

test "a required requirement that is not ok fails, an acceptance-only one does not" {
    var seen: [core_requirements.len]bool = undefined;
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    for (core_requirements) |entry| {
        if (!entry.kind.probeable()) continue;
        const status: Status = if (std.mem.eql(u8, entry.id, "harness-findmnt"))
            .missing
        else
            .ok;
        try buffer.writer.print("{s} id={s} status={s}\n", .{
            report_prefix,
            entry.id,
            status.key(),
        });
    }
    try std.testing.expect(verifyReport(buffer.written(), &seen) == null);

    var failing: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer failing.deinit();
    for (core_requirements) |entry| {
        if (!entry.kind.probeable()) continue;
        const status: Status = if (std.mem.eql(u8, entry.id, "sudo")) .missing else .ok;
        try failing.writer.print("{s} id={s} status={s}\n", .{
            report_prefix,
            entry.id,
            status.key(),
        });
    }
    const rejection = verifyReport(failing.written(), &seen).?;
    try std.testing.expectEqual(Reason.not_satisfied, rejection.reason);
    try std.testing.expectEqualStrings("sudo", rejection.id);
    var message: [256]u8 = undefined;
    const text = describe(rejection, &message);
    try std.testing.expect(std.mem.indexOf(u8, text, "/usr/bin/sudo") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "missing") != null);
}

test "a report that omits a probeable requirement is refused by name" {
    var seen: [core_requirements.len]bool = undefined;
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    for (core_requirements) |entry| {
        if (!entry.kind.probeable()) continue;
        if (std.mem.eql(u8, entry.id, "binder-module")) continue;
        try buffer.writer.print("{s} id={s} status=ok\n", .{ report_prefix, entry.id });
    }
    const rejection = verifyReport(buffer.written(), &seen).?;
    try std.testing.expectEqual(Reason.not_reported, rejection.reason);
    try std.testing.expectEqualStrings("binder-module", rejection.id);
}

test "packages are contract entries but are never probed in the guest" {
    var seen: [core_requirements.len]bool = undefined;
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try completeReport(&buffer);
    try std.testing.expect(verifyReport(buffer.written(), &seen) == null);
    for (core_requirements, 0..) |entry, index| {
        if (entry.kind == .package) try std.testing.expect(!seen[index]);
    }
    try std.testing.expect(!Kind.package.probeable());
    try std.testing.expect(!Kind.package.checkableInRoot());
}

test "a single report answers each named contract that depends on it" {
    const output =
        report_prefix ++ " id=binderfs-mount kind=mount status=ok target=/dev/binderfs\n" ++
        report_prefix ++ " id=dma-heap-system kind=device status=not-writable " ++
        "target=/dev/dma_heap/system\n";
    try std.testing.expectEqual(Status.ok, statusOf(output, "binderfs-mount").?);
    try std.testing.expectEqual(Status.not_writable, statusOf(output, "dma-heap-system").?);
    try std.testing.expect(statusOf(output, "tpm-device") == null);
    try std.testing.expect(statusOf("", "binderfs-mount") == null);
}

test "filesystem lines carry complete ext4 accounting" {
    const line = filesystem_prefix ++ " path=/ block_size=4096 total_blocks=917504 " ++
        "free_blocks=196608 total_inodes=229376 free_inodes=203000";
    const parsed = try parseFilesystemLine(line);
    try std.testing.expectEqualStrings("/", parsed.path);
    try std.testing.expectEqual(@as(u64, 4096), parsed.block_size);
    try std.testing.expectEqual(@as(u64, 917504), parsed.total_blocks);
    try std.testing.expectEqual(@as(u64, 196608), parsed.free_blocks);
    try std.testing.expectEqual(@as(u64, 229376), parsed.total_inodes);
    try std.testing.expectEqual(@as(u64, 203000), parsed.free_inodes);

    try std.testing.expectError(error.Unparseable, parseFilesystemLine("filesystem path=/"));
    try std.testing.expectError(error.Unparseable, parseFilesystemLine(
        filesystem_prefix ++ " path=/ block_size=x total_blocks=1 free_blocks=1 " ++
            "total_inodes=1 free_inodes=1",
    ));
    try std.testing.expectError(error.Unparseable, parseFilesystemLine("other path=/"));
}

test "canonical serialization is one stable line per requirement" {
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try writeCanonical(&buffer.writer);
    var lines: usize = 0;
    var forbidden_lines: usize = 0;
    var iterator = std.mem.splitScalar(u8, buffer.written(), '\n');
    while (iterator.next()) |line| {
        if (line.len == 0) continue;
        var fields: usize = 1;
        for (line) |byte| {
            if (byte == '\t') fields += 1;
        }
        if (std.mem.startsWith(u8, line, forbidden_canonical_prefix ++ "\t")) {
            forbidden_lines += 1;
            try std.testing.expectEqual(@as(usize, 2), fields);
            continue;
        }
        lines += 1;
        try std.testing.expectEqual(@as(usize, 7), fields);
    }
    try std.testing.expectEqual(core_requirements.len, lines);
    // The forbidden set is not derivable from the requirements, so the digest
    // has to carry it or a quietly relaxed exclusion would go unnoticed.
    try std.testing.expectEqual(forbidden_packages.len, forbidden_lines);
}
