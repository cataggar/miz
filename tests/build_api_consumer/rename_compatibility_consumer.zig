const std = @import("std");
const zvmi = @import("zvmi");

test "legacy module alias exposes the current package-family API" {
    try std.testing.expectEqual(@as(u32, 3), zvmi.package_family.api_version);
    try std.testing.expectEqualStrings(
        "e26f05bf18d1b1137a2f9d351253fa917673e918",
        zvmi.package_family.debz_api_commit,
    );
}
