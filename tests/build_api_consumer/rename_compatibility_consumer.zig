const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 4), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "80fa0069f51c0119279b305f5090f00ce72852c5",
        zvmi.package_family.debz_api_commit,
    );
}
