# nbd — native Zig NBD client and reference server

A dependency-free client (and a minimal reference server) for the
[NBD (Network Block Device)](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/nbd.rst) protocol -- a
protocol-only, no-QEMU-internals way to read/write a block device over a
Unix domain or TCP socket. No QEMU C code, no libvirt, no external
dependencies -- just `@import("nbd")` in your `build.zig`.

Part of the Zig-on-QEMU experiment (see issue #4). MIT licensed.

## Status

- [x] Fixed newstyle handshake (oldstyle servers are rejected)
- [x] `NBD_OPT_GO` negotiation, with `NBD_OPT_EXPORT_NAME` fallback for
      servers that predate it
- [x] `NBD_OPT_STRUCTURED_REPLY` negotiation
- [x] `READ` / `WRITE` / `FLUSH` / `TRIM` / `WRITE_ZEROES` / `DISC`, with
      both simple and structured reply parsing (including
      `OFFSET_DATA`/`OFFSET_HOLE`/error chunks)
- [x] `info` / `read` / `write` / `flush` CLI
- [x] Minimal single-connection reference server (`nbd.server`), raw-file
      backed, supporting `NBD_OPT_EXPORT_NAME`/`NBD_OPT_GO`, structured
      replies, and the same transmission commands as the client
- [x] `serve` CLI subcommand exposing the reference server

## Build & test

Requires Zig 0.16. Built as part of the repo-root build graph (there's no
separate `nbd/build.zig`), so run these from the repo root:

```sh
zig build test              # run all tests, including nbd's (pure protocol
                             #   framing + a real Client <-> server test over
                             #   a Unix socket -- no qemu-nbd needed)
zig build                   # build everything, including zig-out/bin/nbd
./zig-out/bin/nbd info unix:/tmp/nbd.sock disk
```

## CLI

```
nbd info  <target> <export>                 print export size + transmission flags
nbd read  <target> <export> <offset> <len>  write raw bytes to stdout
nbd write <target> <export> <offset>        write stdin bytes to the export
nbd flush <target> <export>                 issue NBD_CMD_FLUSH
nbd serve <target> <export> <raw-file>      serve <raw-file> as <export> forever
                                             (<target> must be unix:<path>)
```

`<target>` is `unix:<path>` or `tcp:<host>:<port>`.

## Validation against qemu-nbd / qemu-img / qemu-io

Both directions are cross-checked against the real `qemu-nbd`, `qemu-img`,
and `qemu-io` binaries built from this tree with `zig cc` (see
`scripts/cross-validate.sh` for an automated version of both):

**Client**, against a real `qemu-nbd` server:

```sh
qemu-nbd -f raw --export-name=test -k /tmp/nbd.sock -t -x test disk.raw &
nbd info unix:/tmp/nbd.sock test
# export size:        8388608 bytes
# structured replies: true
# transmission flags: 0xced
#   read-only:         false
#   flush:             true
#   ...
nbd read unix:/tmp/nbd.sock test 0 8388608 | cmp - disk.raw   # byte-for-byte match
nbd write unix:/tmp/nbd.sock test 12345 < patch.bin
nbd flush unix:/tmp/nbd.sock test
```

**Server**, against real `qemu-img`/`qemu-io` acting as NBD clients:

```sh
nbd serve unix:/tmp/srv.sock test disk.raw &
qemu-img info "nbd+unix:///test?socket=/tmp/srv.sock"
qemu-img convert -f raw -O raw "nbd+unix:///test?socket=/tmp/srv.sock" out.raw
cmp disk.raw out.raw   # byte-for-byte match
qemu-io -f raw -c "write -P 0x42 1000 2048" "nbd+unix:///test?socket=/tmp/srv.sock"
qemu-io -f raw -c "read  -P 0x42 1000 2048" "nbd+unix:///test?socket=/tmp/srv.sock"
```

This has been verified end-to-end: a full-disk read, a partial/offset
read, and a write+flush (checked both over NBD and directly against the
backing raw file) against real `qemu-nbd`; and an `info`/`convert`/
`write`+`read` round trip against the from-scratch Zig server, driven by
real `qemu-img`/`qemu-io`.

## Library usage

```zig
const nbd = @import("nbd");

var client = try nbd.Client.connectUnix(allocator, io, "/tmp/nbd.sock", "disk");
defer client.close();

var buf: [4096]u8 = undefined;
try client.read(0, &buf);
try client.write(4096, "hello");
try client.flush();
```

### Reference server (`nbd.server`)

```zig
const nbd = @import("nbd");

var backing = try nbd.server.RawFile.open(io, Io.Dir.cwd(), "disk.raw");
defer backing.close();
try nbd.server.listenAndServeUnix(allocator, io, "/tmp/srv.sock", "disk", &backing);
```

`nbd.server.serveOne` is also exposed directly for handling a single
already-accepted connection (e.g. to serve exactly one client and then
stop, or to plug in a custom accept loop).

Note the reference server is intended for testing `Client` and for manual
interop testing -- it is not hardened against malicious input the way a
production NBD server would need to be.
