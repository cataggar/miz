# qmp — native Zig QMP client

A dependency-free client for the [QEMU Machine Protocol](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/qmp-spec.rst)
(QMP), a JSON-over-socket protocol for driving VM lifecycle automation. No QEMU
C code, no libvirt, no external dependencies — the client links against
nothing but `std` and talks to an unmodified `qemu-system-*` binary over its
`-qmp` control socket.

Part of the Zig-on-QEMU experiment (see issue #3). MIT licensed.

## Status

- [x] Unix domain socket transport
- [x] TCP transport
- [x] Server greeting parsing
- [x] `qmp_capabilities` negotiation handshake
- [x] id-correlated command/response exchange (`Client.execute`)
- [x] Asynchronous event queue (`Client.pollEvent` / `Client.waitEvent`)
- [x] `spawnAndConnect`: launch `qemu-system-*` and connect automatically
- [x] Typed bindings codegen from `qapi/*.json` (stretch goal) — see below
- [x] `greeting` / `exec` / `watch` / `spawn-status` CLI

## Build & test

Requires Zig 0.16. Built as part of the repo-root build graph (there's no
separate `qmp/build.zig`), so run these from the repo root:

```sh
zig build test              # run all tests, including qmp's (pure protocol
                             #   framing, no socket needed)
zig build                   # build everything, including zig-out/bin/{qmp,qapi-codegen}
./zig-out/bin/qmp greeting /tmp/qmp.sock
```

## CLI

```
qmp greeting <socket>                 print the server greeting
qmp exec     <socket> <command> [json-args]
                                       run a command, print its result
qmp watch    <socket> <count>         print <count> events (blocking)
qmp spawn-status <qemu-binary> [extra-args...]
                                       spawn + connect via spawnAndConnect(),
                                       run the typed qapi.queryStatus binding,
                                       then quit
```

## Validation against a real qemu-system-*

Launch a QEMU instance from this tree (built with `zig cc`, see the `zig16`
branch) with a QMP control socket:

```sh
qemu-system-x86_64 -M isapc -display none \
  -qmp unix:/tmp/qmp.sock,server=on,wait=off &
qmp exec /tmp/qmp.sock query-status
# {
#   "status": "running",
#   ...
# }
qmp exec /tmp/qmp.sock quit
```

Or let the client manage the process itself:

```sh
qmp spawn-status qemu-system-x86_64 -M isapc -display none
# running=true status=running
# term=.{ .exited = 0 }
```

See `scripts/cross-validate.sh` for an automated version of these checks
(including `spawnAndConnect` and the typed QAPI bindings).

## Library usage

```zig
const qmp = @import("qmp");

// Connect to an already-running QEMU:
var client = try qmp.Client.connectUnix(allocator, io, "/tmp/qmp.sock");
defer client.close();

// Or spawn one and connect automatically:
var spawned = try qmp.spawnAndConnect(allocator, io, .{
    .binary = "qemu-system-x86_64",
    .extra_args = &.{ "-M", "isapc", "-display", "none" },
    .connect_timeout = .fromSeconds(10),
});
defer spawned.deinit();

// Untyped: any command, raw std.json.Value in and out.
var reply = try client.execute("query-status", null);
defer reply.deinit();
if (reply.err) |e| return error.CommandFailed;
// reply.result is a std.json.Value

// Typed, via the QAPI-generated bindings (see below):
var status = try qmp.qapi.queryStatus(spawned.client, allocator);
defer status.deinit();
std.debug.print("running={}\n", .{status.value.running});

// Deadline-bounded command, status, and child supervision:
const deadline = std.Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
const running = try spawned.client.queryRunningUntil(deadline);
if (running) {
    var quit_reply = try spawned.client.executeUntil("quit", null, deadline);
    defer quit_reply.deinit();
    if (quit_reply.err != null) return error.CommandFailed;
}
_ = try spawned.waitUntil(deadline);
```

`spawnAndConnect` enforces `connect_timeout` across socket creation, the server greeting, and capability negotiation. `executeUntil`, `queryRunningUntil`, and `waitUntil` use an absolute awake-clock deadline and cancel their in-flight operation on expiry.

## Typed QAPI bindings (`qmp.qapi`)

`src/qapi_generated.zig` is generated from QEMU's own QAPI schema
(`qapi/*.json`, 46 files / ~700 command+struct+enum+event definitions) by
`tools/qapi_codegen.zig`, giving statically-typed Zig structs/enums for QAPI
types and typed wrapper functions for QMP commands (`qmp.qapi.queryStatus`,
`qmp.qapi.stop`, `qmp.qapi.deviceAdd`, ...) instead of free-form JSON.

This is a **best-effort, offline generator**, not a build-time dependency of
the `qmp` module — run it manually against a QEMU checkout and commit the
result (from the repo root):

```sh
zig build qapi-codegen -- /path/to/qemu/qapi/qapi-schema.json qmp/src/qapi_generated.zig
zig fmt qmp/src/qapi_generated.zig
```

Known limitations (all degrade gracefully to a `std.json.Value` field/type
rather than failing generation):

- `union` and `alternate` QAPI types are not modeled; anything referencing
  one gets `std.json.Value` instead of a real type.
- Schema `'if'` conditionals (build-time feature gating) are not modeled:
  all enum members are always included, and fields with an `'if'` are
  treated as optional (they may legitimately be absent from a given
  build's wire output). Calling a command an actual build doesn't support
  still fails at runtime with `error.CommandFailed` (`CommandNotFound`),
  same as calling it untyped via `Client.execute`.
- Commands marked `'gen': false` in the schema (e.g. `device_add`, which
  accepts arbitrary driver-specific properties beyond its documented
  fields) aren't generated, matching upstream QEMU's own special-casing —
  use `Client.execute("device_add", args)` directly for these.
- Sending `quit` and then trying to read its reply can race with the
  server closing the connection (more commonly over TCP than Unix
  sockets in local testing) and surface as `error.ReadFailed`
  (`ConnectionResetByPeer`) from `qmp.qapi.quit`/`Client.execute` even
  though the command succeeded and the process did exit. Callers that
  care primarily about the process exiting should tolerate an error from
  the `quit` call itself and check `Spawned.wait()` / process exit
  instead.
