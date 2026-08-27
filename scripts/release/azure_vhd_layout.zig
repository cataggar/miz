//! The Azure fixed-VHD layout constants the release tooling agrees on.
//!
//! Azure derives an uploaded disk's size from the VHD footer rather than from
//! the file length, and only accepts a virtual size that is a whole number of
//! MiB. Both numbers are therefore part of the release contract, not just of
//! the VHD writer: the acceptance harness checks the derived file against
//! them, and the staging gate re-checks the evidence the harness recorded.
//! They live here so every consumer restates the same two values.

pub const alignment: u64 = 1024 * 1024;
pub const footer_bytes: usize = 512;

test "the layout constants are the values Azure documents" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u64, 1024 * 1024), alignment);
    try std.testing.expectEqual(@as(usize, 512), footer_bytes);
}
