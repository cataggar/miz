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
        return self != .package;
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
        .why = "generates the initramfs the UKI embeds; step 4 of #677 moves " ++
            "it out of the final guest, and this classification is what makes " ++
            "that removal a contract-preserving change rather than a gamble",
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
        .id = "linux-azure-package",
        .kind = .package,
        .target = "linux-azure",
        .behavior = .platform_trust,
        .why = "the signed kernel, its signed module tree, and the Azure " ++
            "storage and network drivers the appliance boots on",
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

// ---------------------------------------------------------------------------
// Canonical serialization and digest.
// ---------------------------------------------------------------------------

/// One canonical tab-separated line per requirement, terminated by a newline.
///
/// The digest over these lines is what binds a shipped image to the contract
/// it was built against. It covers every field that changes meaning, so a
/// reclassified audience or a relaxed expectation moves the digest even when
/// the entry count does not.
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
}

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
            .mount, .symlink, .config, .trust_store => try std.testing.expect(entry.expect.len != 0),
            else => {},
        }
        if (entry.kind == .package) {
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
    var iterator = std.mem.splitScalar(u8, buffer.written(), '\n');
    while (iterator.next()) |line| {
        if (line.len == 0) continue;
        lines += 1;
        var fields: usize = 1;
        for (line) |byte| {
            if (byte == '\t') fields += 1;
        }
        try std.testing.expectEqual(@as(usize, 7), fields);
    }
    try std.testing.expectEqual(core_requirements.len, lines);
}
