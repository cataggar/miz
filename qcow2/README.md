# qcow2 — native Zig qcow2 reader

A clean-room implementation of the [qcow2](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/qcow2.rst) disk
image format in Zig. No QEMU C code and no libvirt — just `@import("qcow2")`
in your `build.zig`.

Part of the Zig-on-QEMU experiment (see issue #2). MIT licensed.

## Status

- [x] Header parsing (v2 / v3), feature-bit validation
- [x] L1/L2 cluster mapping (standard / zero / unallocated / compressed)
- [x] `read(guest_offset, buf)` for uncompressed images
- [x] Compressed clusters (deflate / zstd)
- [x] `info` / `map` / `read` CLI
- [x] Backing-file chains
- [x] Extended L2 (subcluster) entries
- [x] Writer / image creation (`convert` raw → qcow2)
- [x] Refcount table + basic consistency check (`check`)
- [x] Snapshots (table parsing + read-only access)

## Build & test

Requires Zig 0.16. Built as part of the repo-root build graph (there's no
separate `qcow2/build.zig`), so run these from the repo root:

```sh
zig build test              # run all tests, including qcow2's
zig build                   # build everything, including zig-out/bin/qcow2
./zig-out/bin/qcow2 info disk.qcow2
```

## CLI

```
qcow2 info <image>                 dump header + feature summary
qcow2 map  <image> <offset>        classify the cluster at a guest offset
qcow2 read <image> <offset> <len> [--snapshot=<id>]
                                    write raw guest (or snapshot) bytes to stdout
qcow2 check <image>                basic refcount/consistency check
qcow2 snapshots <image>            list the snapshot directory
qcow2 convert <raw_in> <qcow2_out> create a qcow2 image from a raw file
```

## Validation against qemu-img

The reader is cross-checked against the `qemu-img` binary built from this tree
with `zig cc`. For example:

```sh
# create an Extended L2 qcow2, populate a few subclusters, then compare
qemu-img create -f qcow2 -o extended_l2=on,cluster_size=64k ext.qcow2 4M
qemu-io -c "write -s pattern.bin 0 2048" ext.qcow2
qemu-io -c "write -z 4096 2048" ext.qcow2
qemu-img convert -O raw ext.qcow2 expected.raw
qcow2 read ext.qcow2 0 4194304 | cmp - expected.raw
```

This has been verified byte-for-byte (via `cmp`) against real `qemu-img`/
`qemu-io`-produced images for: standard v3 images, Extended L2 images with
mixed allocated/zero/unallocated subclusters across multiple L2 tables,
Extended L2 + backing-file chains, and — in the other direction — images
produced by this crate's own writer (`extended_l2 = true`) opened and
`check`ed/`convert`ed successfully by `qemu-img`. `qcow2 check`'s clean/dirty
verdict is also cross-checked against real `qemu-img check` on the same
images, and `qcow2 read --snapshot=<id>` is cross-checked against
`qemu-img convert -l <id>` on an image with a real `qemu-img snapshot -c`
snapshot (see `scripts/cross-validate.sh`).

## Library usage

```zig
const qcow2 = @import("qcow2");

var img = try qcow2.Image.open(allocator, io, std.Io.Dir.cwd(), "disk.qcow2");
defer img.close();

var buf: [4096]u8 = undefined;
try img.read(0, &buf);
```
