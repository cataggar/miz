//! Exact same-architecture QEMU execution profiles for Ubuntu acceptance.
//!
//! x86_64 remains hardware-accelerated and fail-closed on KVM. AArch64 runs
//! on GitHub's native Arm64 hosted runner with QEMU TCG because the hosted
//! platform exposes no Arm64 KVM device. Neither profile permits accelerator
//! discovery, fallback, or cross-architecture execution.

const std = @import("std");

pub const Architecture = enum { x86_64, aarch64 };

pub const Accelerator = enum { kvm, tcg };

/// Controls whether the second identity-provisioning first boot may begin
/// before the first guest has passed its flavor-specific readiness checks.
pub const InitialGuestLaunchPolicy = enum {
    concurrent,
    serial_until_ready,
};

pub const TimeoutPolicy = struct {
    job_minutes: u16,
    qmp_connect_seconds: i64,
    guest_ready_seconds: i64,
    ssh_connect_seconds: u16,
    ssh_poll_seconds: i64,
    ssh_command_seconds: i64,
    ssh_long_command_seconds: i64,
    tamper_control_seconds: i64,
    tamper_refusal_seconds: i64,
};

pub const Profile = struct {
    architecture: Architecture,
    accelerator: Accelerator,
    accelerator_argument: []const u8,
    emulator: []const u8,
    runner_architecture: []const u8,
    machine: []const u8,
    cpu: []const u8,
    initial_guest_launch: InitialGuestLaunchPolicy,
    timeouts: TimeoutPolicy,
};

pub const x86_64_kvm: Profile = .{
    .architecture = .x86_64,
    .accelerator = .kvm,
    .accelerator_argument = "kvm",
    .emulator = "/usr/bin/qemu-system-x86_64",
    .runner_architecture = "x86_64",
    .machine = "q35",
    .cpu = "host",
    .initial_guest_launch = .concurrent,
    .timeouts = .{
        .job_minutes = 180,
        .qmp_connect_seconds = 30,
        .guest_ready_seconds = 8 * 60,
        .ssh_connect_seconds = 5,
        .ssh_poll_seconds = 20,
        .ssh_command_seconds = 20,
        .ssh_long_command_seconds = 20,
        .tamper_control_seconds = 90,
        .tamper_refusal_seconds = 60,
    },
};

pub const aarch64_tcg: Profile = .{
    .architecture = .aarch64,
    .accelerator = .tcg,
    .accelerator_argument = "tcg,thread=multi",
    .emulator = "/usr/bin/qemu-system-aarch64",
    .runner_architecture = "aarch64",
    .machine = "virt",
    .cpu = "max",
    .initial_guest_launch = .serial_until_ready,
    .timeouts = .{
        .job_minutes = 360,
        .qmp_connect_seconds = 2 * 60,
        .guest_ready_seconds = 45 * 60,
        .ssh_connect_seconds = 30,
        .ssh_poll_seconds = 2 * 60,
        .ssh_command_seconds = 2 * 60,
        .ssh_long_command_seconds = 15 * 60,
        .tamper_control_seconds = 20 * 60,
        .tamper_refusal_seconds = 10 * 60,
    },
};

pub const identity_fields = [_][]const u8{
    "accelerator",
    "cpu",
    "emulator",
    "guest_architecture",
    "machine",
    "runner_architecture",
};

pub fn forArchitecture(architecture: Architecture) *const Profile {
    return switch (architecture) {
        .x86_64 => &x86_64_kvm,
        .aarch64 => &aarch64_tcg,
    };
}

pub fn forName(architecture: []const u8) ?*const Profile {
    const parsed = std.meta.stringToEnum(Architecture, architecture) orelse
        return null;
    return forArchitecture(parsed);
}

test "Ubuntu QEMU execution profiles are exact and fail closed" {
    try std.testing.expectEqual(Accelerator.kvm, x86_64_kvm.accelerator);
    try std.testing.expectEqualStrings("kvm", x86_64_kvm.accelerator_argument);
    try std.testing.expectEqualStrings("host", x86_64_kvm.cpu);
    try std.testing.expectEqualStrings("q35", x86_64_kvm.machine);
    try std.testing.expectEqual(
        InitialGuestLaunchPolicy.concurrent,
        x86_64_kvm.initial_guest_launch,
    );
    try std.testing.expectEqual(@as(u16, 180), x86_64_kvm.timeouts.job_minutes);

    try std.testing.expectEqual(Accelerator.tcg, aarch64_tcg.accelerator);
    try std.testing.expectEqualStrings(
        "tcg,thread=multi",
        aarch64_tcg.accelerator_argument,
    );
    try std.testing.expectEqualStrings("max", aarch64_tcg.cpu);
    try std.testing.expectEqualStrings("virt", aarch64_tcg.machine);
    try std.testing.expectEqual(
        InitialGuestLaunchPolicy.serial_until_ready,
        aarch64_tcg.initial_guest_launch,
    );
    try std.testing.expectEqual(@as(u16, 360), aarch64_tcg.timeouts.job_minutes);
    try std.testing.expect(
        aarch64_tcg.timeouts.guest_ready_seconds >
            x86_64_kvm.timeouts.guest_ready_seconds,
    );

    for (identity_fields[1..], identity_fields[0 .. identity_fields.len - 1]) |
        field,
        previous,
    | {
        try std.testing.expect(std.mem.lessThan(u8, previous, field));
    }
    for ([_]*const Profile{ &x86_64_kvm, &aarch64_tcg }) |profile| {
        try std.testing.expect(
            std.mem.indexOf(u8, profile.accelerator_argument, "auto") == null,
        );
        try std.testing.expectEqualStrings(
            @tagName(profile.architecture),
            profile.runner_architecture,
        );
    }
}
