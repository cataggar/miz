//! Mixed-endian GUID encoding, as used by GPT (partition type/unique GUIDs,
//! disk GUID) and Microsoft's `GUID`/`UUID` struct convention generally.
//!
//! A GUID's canonical string form `AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP`
//! is *not* stored as 16 big-endian bytes in binary form (unlike the VHD
//! footer's `unique_id`, which is plain big-endian/network-order bytes).
//! Instead the first three fields are little-endian and the last two are
//! stored byte-for-byte as they appear in the string:
//!   bytes[0..4]   = Data1 (AABBCCDD), little-endian
//!   bytes[4..6]   = Data2 (EEFF), little-endian
//!   bytes[6..8]   = Data3 (GGHH), little-endian
//!   bytes[8..16]  = Data4 (IIJJKKLLMMNNOOPP), as-is

const std = @import("std");

pub const Guid = [16]u8;

/// Formats a mixed-endian binary GUID as a lowercase canonical string
/// (`aabbccdd-eeff-gghh-iijj-kkllmmnnoopp`).
pub fn formatLower(buf: *[36]u8, value: Guid) []const u8 {
    const data1 = std.mem.readInt(u32, value[0..4], .little);
    const data2 = std.mem.readInt(u16, value[4..6], .little);
    const data3 = std.mem.readInt(u16, value[6..8], .little);
    _ = std.fmt.bufPrint(
        buf,
        "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            data1,
            data2,
            data3,
            value[8],
            value[9],
            value[10],
            value[11],
            value[12],
            value[13],
            value[14],
            value[15],
        },
    ) catch unreachable;
    return buf;
}

/// Parses a canonical `AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP` string (case
/// insensitive) into its mixed-endian binary form. Intended primarily for
/// `comptime`-evaluating the well-known constants below, but works at
/// runtime too.
pub fn parse(str: []const u8) Guid {
    std.debug.assert(str.len == 36);
    std.debug.assert(str[8] == '-' and str[13] == '-' and str[18] == '-' and str[23] == '-');

    var hex_only: [32]u8 = undefined;
    var out_i: usize = 0;
    for (str) |c| {
        if (c == '-') continue;
        hex_only[out_i] = c;
        out_i += 1;
    }
    std.debug.assert(out_i == 32);

    var raw: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        raw[i] = std.fmt.parseInt(u8, hex_only[i * 2 ..][0..2], 16) catch unreachable;
    }

    // raw[0..4]=Data1 (big-endian as parsed), raw[4..6]=Data2, raw[6..8]=Data3,
    // raw[8..16]=Data4. Byte-swap the first three fields to little-endian;
    // Data4 stays as-is.
    return .{
        raw[3],  raw[2],  raw[1],  raw[0],
        raw[5],  raw[4],  raw[7],  raw[6],
        raw[8],  raw[9],  raw[10], raw[11],
        raw[12], raw[13], raw[14], raw[15],
    };
}

/// EFI System Partition (ESP) type GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
pub const esp: Guid = parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");

/// Linux filesystem data type GUID (the standard type for a plain Linux
/// root/data partition on GPT, as used by systemd-gpt-auto-generator, gdisk,
/// etc.): 0FC63DAF-8483-4772-8E79-3D69D8477DE4.
pub const linux_filesystem_data: Guid = parse("0FC63DAF-8483-4772-8E79-3D69D8477DE4");

/// Linux LVM physical volume type GUID, which a guided Ubuntu or Debian
/// install puts on the partition holding the volume group:
/// E6D6D379-F507-44C2-A23C-238F2A3DF928. Only a hint -- `lvm.scan` looks for
/// an LVM2 label in every partition regardless of type -- but worth naming
/// where a layout is described.
pub const linux_lvm: Guid = parse("E6D6D379-F507-44C2-A23C-238F2A3DF928");

/// Discoverable Partitions Specification root (`/`) type GUID for x86-64:
/// 4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709.
pub const linux_root_x86_64: Guid = parse("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");

/// Discoverable Partitions Specification root (`/`) type GUID for
/// 64-bit ARM/AArch64: B921B045-1DF0-41C3-AF44-4C6F280D3FAE.
pub const linux_root_aarch64: Guid = parse("B921B045-1DF0-41C3-AF44-4C6F280D3FAE");

/// Discoverable Partitions Specification `/usr/` type GUID for x86-64:
/// 8484680C-9521-48C6-9C11-B0720656F69E.
pub const linux_usr_x86_64: Guid = parse("8484680C-9521-48C6-9C11-B0720656F69E");

/// Discoverable Partitions Specification `/usr/` type GUID for
/// 64-bit ARM/AArch64: B0E01050-EE5F-4390-949A-9101B17104E9.
pub const linux_usr_aarch64: Guid = parse("B0E01050-EE5F-4390-949A-9101B17104E9");

/// Discoverable Partitions Specification XBOOTLDR (`/boot/`) type GUID:
/// BC13C2FF-59E6-4262-A352-B275FD6F7172.
pub const linux_xbootldr: Guid = parse("BC13C2FF-59E6-4262-A352-B275FD6F7172");

/// Microsoft Basic Data type GUID (Windows data volumes; included for
/// completeness): EBD0A0A2-B9E5-4433-87C0-68B6B72699C7.
pub const microsoft_basic_data: Guid = parse("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");

/// A GUID with all bytes zero, used for "no partition" / unused entries.
pub const nil: Guid = [_]u8{0} ** 16;

test "formatLower reverses parse" {
    var buf: [36]u8 = undefined;
    try std.testing.expectEqualStrings(
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        formatLower(&buf, esp),
    );
}

test "parse produces the well-known ESP GUID bytes" {
    // Cross-checked against the UEFI spec / Wikipedia's GPT article: the
    // canonical string C12A7328-F81F-11D2-BA4B-00A0C93EC93B encodes with
    // Data1/2/3 byte-swapped to little-endian and Data4 left as-is.
    const expected: Guid = .{
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
        0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
    };
    try std.testing.expectEqualSlices(u8, &expected, &esp);
}
