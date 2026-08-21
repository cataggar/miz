const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 3), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "b2445dbfdd4e19e0412e934cdc04cdcd1280ced7",
        zvmi.package_family.debz_api_commit,
    );
}
