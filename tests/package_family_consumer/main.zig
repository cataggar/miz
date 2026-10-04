const std = @import("std");
const host = @import("package_family_host");

test "public host adapter is available independently of repository name" {
    try std.testing.expectEqualStrings(
        "c9b23a2103b9682434ab663841d00cd657647561",
        host.rpmz_commit,
    );
    try std.testing.expectEqual(
        host.package_family.RpmBackend.rpmz,
        @as(host.package_family.RpmBackend, .rpmz),
    );
}
