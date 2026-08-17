const std = @import("std");
const package_family = @import("vmiz").package_family;

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
        },
    };
    try std.testing.expectEqual(package_family.Operation.resolve_lock, resolve.operation);
    try std.testing.expectEqualStrings(
        "d5385857a44fca753af515e805af70be9f004183",
        package_family.debz_api_commit,
    );
}
