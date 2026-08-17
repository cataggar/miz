const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 3), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "d5385857a44fca753af515e805af70be9f004183",
        zvmi.package_family.debz_api_commit,
    );
}
