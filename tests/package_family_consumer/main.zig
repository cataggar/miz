const std = @import("std");
const host = @import("package_family_host");

test "public host adapter is available independently of repository name" {
    try std.testing.expectEqualStrings(
        "15b5e1291a9fc3eb3980a4088d757b9d0254d468",
        host.rpmz_commit,
    );
    try std.testing.expectEqual(
        host.package_family.RpmBackend.rpmz,
        @as(host.package_family.RpmBackend, .rpmz),
    );
}
