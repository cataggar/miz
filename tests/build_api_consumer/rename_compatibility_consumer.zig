const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 4), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "beac3f20dd93fd98863af71e8fe621d47db663f6",
        zvmi.package_family.debz_api_commit,
    );
}
