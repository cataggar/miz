const std = @import("std");
const package_family = @import("miz").package_family;

test "public consumer can model lock review and locked creation" {
    const resolve: package_family.Request = .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .resolve_lock,
        .packages = &.{"ubuntu-minimal"},
        .inputs = .{
            .root_stage = "/build/ubuntu-stage",
            .published_root = "/build/ubuntu",
            .architecture = .amd64,
            .source_paths = &.{"/inputs/ubuntu.sources"},
            .keyring_paths = &.{"/inputs/ubuntu.gpg"},
            .cache_path = "/cache/debz",
            .state_path = "/state/debz",
            .lock_output_path = "/locks/ubuntu.lock",
            .installed_baseline = .require_locked,
        },
    };
    try std.testing.expectEqual(package_family.Operation.resolve_lock, resolve.operation);
    try std.testing.expectEqual(
        package_family.InstalledBaselinePolicy.require_locked,
        resolve.inputs.installed_baseline,
    );
    try std.testing.expectEqualStrings(
        "56be0a32fac5293f20bde45d266b708e53321c73",
        package_family.debz_api_commit,
    );
}
