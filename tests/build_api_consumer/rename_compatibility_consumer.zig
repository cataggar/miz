const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 3), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "f46153f8d3d0318969104ed23d172ead8256c1ac",
        zvmi.package_family.debz_api_commit,
    );
}
