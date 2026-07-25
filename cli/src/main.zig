//! `zvmi`: a qemu-img-like CLI over the `zvmi` library. Supports `create`,
//! `info`, `convert`, `resize`, `check`, `map`, `build-image`, `azure`,
//! `cosi`, `oci`, `qemu`, and release signing over `raw`, `vhd`, `vhdx`, and
//! `qcow2`.

const std = @import("std");
const zvmi = @import("zvmi");

const create_cmd = @import("commands/create.zig");
const info_cmd = @import("commands/info.zig");
const convert_cmd = @import("commands/convert.zig");
const resize_cmd = @import("commands/resize.zig");
const check_cmd = @import("commands/check.zig");
const map_cmd = @import("commands/map.zig");
const azure_cmd = @import("commands/azure.zig");
const cosi_cmd = @import("commands/cosi.zig");
const build_image_cmd = @import("commands/build_image.zig");
const qemu_cmd = @import("commands/qemu.zig");
const sign_cmd = @import("commands/sign.zig");
const oci_cmd = @import("commands/oci.zig");
const uki_cmd = @import("commands/uki.zig");

const usage =
    \\Usage: zvmi <command> [options]
    \\
    \\Commands:
    \\  create -f <format> [-o subformat=fixed|dynamic] <file> <size>
    \\  info [--output=human|json] <file>
    \\  convert -f <src_format> -O <dst_format> [-o subformat=fixed|dynamic] <src> <dst>
    \\  resize <file> [+]<size>
    \\  check <file>
    \\  map [--output=human|json] <file>
    \\  azure derive --input-sha256 <hex> [--expected-virtual-size <size>] <input.qcow2> <output.vhd>
    \\  azure fixup [--generation 1|2] <file>  # defaults to Gen2; non-VHD becomes <basename>.vhd
    \\  azure deprovision [--user <username>] <file>
    \\  cosi <disk-image> -o <output.cosi>
    \\  oci copy|inspect|list-tags
    \\  build-image --iso <file.iso> --container <oci-layout> [--generation 1|2] --size <size> -o <output.{{raw|vhd|vhdx|qcow2}}> [--skip-iso-rootfs] [--esp-size <size>] [--root-selinux-label <context>] [--boot-mode bls|uki|both] [--stub-source-path <path>] [--verity]
    \\  qemu [<image>] [--model full|core] [--architecture auto|x86_64|aarch64] [--admin-username <name>] [--ssh-public-key <path>] [--ssh-port <port>] [--snapshot] [--secure-boot] [--secure-boot-certificate <path> --secure-boot-certificate-sha256 <hex>] [--accel auto|whpx|kvm|hvf|tcg] [--qemu <path>] [--ovmf-code <path>] [--ovmf-vars <path>] [-- <extra-qemu-args...>]
    \\  uki certificate <disk-image> (--output <certificate.pem>|--output=json) [--expected-sha256 <hex>]
    \\  sign
    \\
    \\Formats: raw, vhd (alias: vpc), vhdx, qcow2
    \\Sizes accept K/M/G/T binary suffixes (e.g. 20G).
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    const exit_code = run(gpa, io, init.minimal.environ, argv[1..]);
    std.process.exit(exit_code);
}

fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    args: []const []const u8,
) u8 {
    if (args.len < 1) {
        std.debug.print("{s}", .{usage});
        return 1;
    }

    const command = args[0];
    const rest = args[1..];

    if (std.mem.eql(u8, command, "create")) return create_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "info")) return info_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "convert")) return convert_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "resize")) return resize_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "check")) return check_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "map")) return map_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "azure")) return azure_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "cosi")) return cosi_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "build-image")) return build_image_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "qemu")) return qemu_cmd.run(gpa, io, environ, rest);
    if (std.mem.eql(u8, command, "sign")) return sign_cmd.run(gpa, io, environ, rest);
    if (std.mem.eql(u8, command, "oci")) return oci_cmd.run(gpa, io, environ, rest);
    if (std.mem.eql(u8, command, "uki")) return uki_cmd.run(gpa, io, rest);
    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "help")) {
        std.debug.print("{s}", .{usage});
        return 0;
    }
    std.debug.print("zvmi: unknown command '{s}'\n\n{s}", .{ command, usage });
    return 1;
}

test {
    _ = create_cmd;
    _ = info_cmd;
    _ = convert_cmd;
    _ = resize_cmd;
    _ = check_cmd;
    _ = map_cmd;
    _ = azure_cmd;
    _ = cosi_cmd;
    _ = build_image_cmd;
    _ = qemu_cmd;
    _ = sign_cmd;
    _ = oci_cmd;
    _ = uki_cmd;
}
