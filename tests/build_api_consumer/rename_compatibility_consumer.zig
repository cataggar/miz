const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 4), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "9cabfc0f808a8beb4709d7e5b3ae7baf19d733d5",
        zvmi.package_family.debz_api_commit,
    );
}
