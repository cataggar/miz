//! Native Zig QMP (QEMU Machine Protocol) client.
//!
//! A dependency-free client for the JSON-over-socket protocol QEMU exposes
//! for machine-level control (see `docs/interop/qmp-spec.rst` in the QEMU
//! tree). No QEMU C code, no libvirt — the client links against nothing but
//! `std`, and talks to an unmodified `qemu-system-*` binary over its `-qmp`
//! control socket.
//!
//! Scope: Unix domain socket transport, the greeting + `qmp_capabilities`
//! capabilities-negotiation handshake, id-correlated command/response
//! exchange (`Client.execute`), and asynchronous server-pushed events
//! (`Client.pollEvent` / `Client.waitEvent`).
//!
//! The wire framing/classification logic (`readFrame` / `writeCommand`) is
//! transport-agnostic — it operates on `std.Io.Reader`/`std.Io.Writer`
//! directly, so it can be unit-tested against in-memory buffers without a
//! real socket or a running QEMU.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;

/// Typed bindings generated from QEMU's QAPI schema (`qapi/*.json`) by
/// `tools/qapi_codegen.zig` -- see zig/qmp/README.md for coverage and
/// limitations. Best-effort: consumers can always fall back to
/// `Client.execute` directly for anything not (yet) covered here.
pub const qapi = @import("qapi_generated.zig");

/// A server-reported command error: `{"error": {"class", "desc"}}`.
pub const CommandError = struct {
    class: []const u8,
    desc: []const u8,
};

/// A command response, matched to the `execute()` call that produced it via
/// `id`. Exactly one of `result` / `err` is non-null.
pub const Reply = struct {
    parsed: std.json.Parsed(std.json.Value),
    id: ?u64,
    result: ?std.json.Value,
    err: ?CommandError,

    pub fn deinit(self: Reply) void {
        self.parsed.deinit();
    }
};

/// An asynchronous event pushed by the server, e.g. `SHUTDOWN`, `RESET`,
/// `BLOCK_JOB_COMPLETED`.
pub const EventMsg = struct {
    parsed: std.json.Parsed(std.json.Value),
    name: []const u8,
    data: ?std.json.Value,
    /// Seconds/microseconds since the Unix epoch, or -1 if the server failed
    /// to retrieve host time (per the QMP spec), or if absent entirely.
    seconds: i64,
    microseconds: i64,

    pub fn deinit(self: EventMsg) void {
        self.parsed.deinit();
    }
};

/// The result of classifying one newline-delimited JSON message from the
/// wire: the initial server greeting, an asynchronous event, or a command
/// response (success or error).
pub const ParsedLine = union(enum) {
    greeting: std.json.Parsed(std.json.Value),
    event: EventMsg,
    reply: Reply,
};

/// Read one CRLF- (or LF-) terminated JSON message from `r` and classify it.
///
/// Transport-agnostic: `r` may be backed by a real socket or, in tests, by
/// `std.Io.Reader.fixed`.
pub fn readFrame(allocator: std.mem.Allocator, r: *Io.Reader) !ParsedLine {
    // `takeDelimiterExclusive` leaves the delimiter itself unconsumed in the
    // stream (by design, so callers can inspect it), which would make the
    // *next* read immediately see a stray leftover `\n`. Use the inclusive
    // variant, which advances past the delimiter, and strip it ourselves.
    const inclusive = try r.takeDelimiterInclusive('\n');
    const line = std.mem.trimEnd(u8, inclusive[0 .. inclusive.len - 1], "\r");

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    errdefer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedResponse,
    };

    if (obj.contains("QMP")) return .{ .greeting = parsed };

    if (obj.get("event")) |ev_val| {
        const name = switch (ev_val) {
            .string => |s| s,
            else => return error.UnexpectedResponse,
        };
        var seconds: i64 = -1;
        var microseconds: i64 = -1;
        if (obj.get("timestamp")) |ts_val| {
            if (ts_val == .object) {
                if (ts_val.object.get("seconds")) |s| {
                    if (s == .integer) seconds = s.integer;
                }
                if (ts_val.object.get("microseconds")) |m| {
                    if (m == .integer) microseconds = m.integer;
                }
            }
        }
        return .{ .event = .{
            .parsed = parsed,
            .name = name,
            .data = obj.get("data"),
            .seconds = seconds,
            .microseconds = microseconds,
        } };
    }

    const id: ?u64 = if (obj.get("id")) |v| switch (v) {
        .integer => |n| if (n >= 0) @as(u64, @intCast(n)) else return error.UnexpectedResponse,
        else => return error.UnexpectedResponse,
    } else null;

    if (obj.get("return")) |ret| {
        return .{ .reply = .{ .parsed = parsed, .id = id, .result = ret, .err = null } };
    }

    if (obj.get("error")) |err_val| {
        if (err_val != .object) return error.UnexpectedResponse;
        const class_val = err_val.object.get("class") orelse return error.UnexpectedResponse;
        const desc_val = err_val.object.get("desc") orelse return error.UnexpectedResponse;
        const class = switch (class_val) {
            .string => |s| s,
            else => return error.UnexpectedResponse,
        };
        const desc = switch (desc_val) {
            .string => |s| s,
            else => return error.UnexpectedResponse,
        };
        return .{ .reply = .{
            .parsed = parsed,
            .id = id,
            .result = null,
            .err = .{ .class = class, .desc = desc },
        } };
    }

    return error.UnexpectedResponse;
}

/// Write `{"execute": name, "arguments": args?, "id": id}` followed by a
/// newline, and flush.
///
/// Transport-agnostic: `w` may be backed by a real socket or, in tests, by
/// `std.Io.Writer.fixed`.
pub fn writeCommand(w: *Io.Writer, name: []const u8, args: ?std.json.Value, id: u64) !void {
    var stringify: std.json.Stringify = .{ .writer = w };
    try stringify.beginObject();
    try stringify.objectField("execute");
    try stringify.write(name);
    if (args) |a| {
        try stringify.objectField("arguments");
        try stringify.write(a);
    }
    try stringify.objectField("id");
    try stringify.write(id);
    try stringify.endObject();
    try w.writeByte('\n');
    try w.flush();
}

/// Converts any `std.json.Stringify`-serializable value (e.g. a plain Zig
/// struct, as produced by the QAPI-generated typed command bindings in
/// `qapi_generated.zig`) into a `std.json.Value`, by round-tripping it
/// through JSON text. Used to bridge typed argument structs into
/// `Client.execute`'s `?std.json.Value` parameter.
pub fn valueFromAny(allocator: std.mem.Allocator, value: anytype) !std.json.Parsed(std.json.Value) {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    defer buf.deinit();
    try std.json.Stringify.value(value, .{}, &buf.writer);
    return std.json.parseFromSlice(std.json.Value, allocator, buf.written(), .{});
}

/// A connected QMP session: a Unix domain socket to a `qemu-system-*` (or
/// QEMU Guest Agent) `-qmp` control socket, past the greeting +
/// `qmp_capabilities` handshake.
///
/// Heap-allocated (via `connectUnix`) so the read/write buffers embedded in
/// it have a stable address for the lifetime of the connection.
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    read_buf: [8192]u8 = undefined,
    write_buf: [4096]u8 = undefined,
    stream_reader: net.Stream.Reader = undefined,
    stream_writer: net.Stream.Writer = undefined,
    next_id: u64 = 1,
    /// Events observed while blocked in `execute()`, awaiting queued
    /// draining via `pollEvent`/`waitEvent`.
    events: std.ArrayList(EventMsg) = .empty,
    greeting: std.json.Parsed(std.json.Value) = undefined,

    /// Connect to the Unix domain socket at `path`, perform the greeting +
    /// `qmp_capabilities` handshake, and return a ready-to-use client.
    pub fn connectUnix(allocator: std.mem.Allocator, io: Io, path: []const u8) !*Client {
        const addr = try net.UnixAddress.init(path);
        const stream = try addr.connect(io);
        errdefer stream.close(io);
        return connectStream(allocator, io, stream);
    }

    /// Connect to a TCP `-qmp tcp:host:port,server=on,wait=off` control
    /// socket at `address`, perform the greeting + `qmp_capabilities`
    /// handshake, and return a ready-to-use client.
    pub fn connectTcp(allocator: std.mem.Allocator, io: Io, address: net.IpAddress) !*Client {
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        return connectStream(allocator, io, stream);
    }

    /// Shared handshake logic for an already-connected `stream` (Unix or
    /// TCP). Takes ownership of `stream` (closed by `Client.close`, or by
    /// the caller if this function returns an error).
    fn connectStream(allocator: std.mem.Allocator, io: Io, stream: net.Stream) !*Client {
        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
        };
        self.stream_reader = net.Stream.Reader.init(self.stream, io, &self.read_buf);
        self.stream_writer = net.Stream.Writer.init(self.stream, io, &self.write_buf);

        const first = try readFrame(allocator, &self.stream_reader.interface);
        switch (first) {
            .greeting => |g| self.greeting = g,
            .event => |e| {
                e.deinit();
                return error.UnexpectedGreeting;
            },
            .reply => |r| {
                r.deinit();
                return error.UnexpectedGreeting;
            },
        }
        errdefer self.greeting.deinit();

        var caps = try self.execute("qmp_capabilities", null);
        defer caps.deinit();
        if (caps.err != null) return error.CommandFailed;

        return self;
    }

    pub fn close(self: *Client) void {
        self.stream.close(self.io);
        self.greeting.deinit();
        for (self.events.items) |e| e.deinit();
        self.events.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Send `name` (with optional `arguments`) and block until the
    /// correlated response arrives. Events observed while waiting are
    /// queued; drain them with `pollEvent`/`waitEvent`. Caller owns the
    /// returned `Reply` and must call `.deinit()`.
    pub fn execute(self: *Client, name: []const u8, args: ?std.json.Value) !Reply {
        const id = self.next_id;
        self.next_id += 1;
        try writeCommand(&self.stream_writer.interface, name, args, id);

        while (true) {
            const msg = try readFrame(self.allocator, &self.stream_reader.interface);
            switch (msg) {
                .greeting => |g| {
                    g.deinit();
                    return error.UnexpectedResponse;
                },
                .event => |e| try self.events.append(self.allocator, e),
                .reply => |r| {
                    if (r.id != null and r.id.? == id) return r;
                    // QMP without out-of-band execution replies in issue
                    // order, so this shouldn't happen; don't silently drop
                    // what looks like a real reply.
                    r.deinit();
                    return error.UnexpectedResponse;
                },
            }
        }
    }

    /// Executes one command while enforcing an absolute awake-clock deadline.
    /// A timeout cancels the in-flight socket operation; the caller should
    /// close the client rather than issuing another command afterward.
    pub fn executeUntil(
        self: *Client,
        name: []const u8,
        args: ?std.json.Value,
        deadline: Io.Timestamp,
    ) !Reply {
        const timeout_duration = try remainingDuration(self.io, deadline);
        const ExecuteResult = @typeInfo(
            @TypeOf(Client.execute),
        ).@"fn".return_type.?;
        const Selection = union(enum) {
            reply: ExecuteResult,
            timeout: Io.Cancelable!void,
        };
        var buffer: [2]Selection = undefined;
        var select = Io.Select(Selection).init(self.io, &buffer);
        select.async(.reply, Client.execute, .{ self, name, args });
        select.async(
            .timeout,
            Io.sleep,
            .{ self.io, timeout_duration, .awake },
        );
        const selected = select.await() catch |err| {
            while (select.cancel()) |remaining| {
                switch (remaining) {
                    .reply => |reply_result| {
                        if (reply_result) |reply_value| {
                            var reply = reply_value;
                            reply.deinit();
                        } else |_| {}
                    },
                    .timeout => |timeout_result| timeout_result catch {},
                }
            }
            return err;
        };
        switch (selected) {
            .reply => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => |result| {
                try result;
                while (select.cancel()) |remaining| {
                    switch (remaining) {
                        .reply => |reply_result| {
                            if (reply_result) |reply_value| {
                                var reply = reply_value;
                                reply.deinit();
                            } else |_| {}
                        },
                        .timeout => |timeout_result| timeout_result catch {},
                    }
                }
                return error.QmpTimedOut;
            },
        }
    }

    /// Returns QEMU's current `running` status before `deadline`.
    pub fn queryRunningUntil(
        self: *Client,
        deadline: Io.Timestamp,
    ) !bool {
        var reply = try self.executeUntil("query-status", null, deadline);
        defer reply.deinit();
        if (reply.err != null) return error.CommandFailed;
        const result = reply.result orelse return error.UnexpectedResponse;
        if (result != .object) return error.UnexpectedResponse;
        const running = result.object.get("running") orelse
            return error.UnexpectedResponse;
        if (running != .bool) return error.UnexpectedResponse;
        return running.bool;
    }

    /// Pop the oldest queued event, if any, without blocking on the socket.
    /// Caller owns the result and must call `.deinit()`.
    pub fn pollEvent(self: *Client) ?EventMsg {
        if (self.events.items.len == 0) return null;
        return self.events.orderedRemove(0);
    }

    /// Block until the next event arrives, draining any already-queued
    /// events first. Caller owns the result and must call `.deinit()`.
    pub fn waitEvent(self: *Client) !EventMsg {
        if (self.pollEvent()) |e| return e;
        while (true) {
            const msg = try readFrame(self.allocator, &self.stream_reader.interface);
            switch (msg) {
                .greeting => |g| {
                    g.deinit();
                    return error.UnexpectedResponse;
                },
                .event => |e| return e,
                .reply => |r| {
                    // A reply with no in-flight `execute()` awaiting it.
                    r.deinit();
                    return error.UnexpectedResponse;
                },
            }
        }
    }
};

/// Options for `spawnAndConnect`.
pub const SpawnOptions = struct {
    /// Path to the `qemu-system-*` (or other QMP-speaking) binary to launch.
    binary: []const u8,
    /// Extra argv entries, inserted between `binary` and the
    /// auto-generated `-qmp unix:<path>,server=on,wait=off`. Typically at
    /// least `&.{"-display", "none"}` or similar.
    extra_args: []const []const u8 = &.{},
    /// Path for the QMP Unix domain control socket. If null, a path under
    /// the system temp directory is generated.
    qmp_socket_path: ?[]const u8 = null,
    /// How long to keep retrying the initial connection while the child
    /// starts up and creates its QMP socket.
    connect_timeout: Io.Duration = .fromSeconds(10),
    /// How long to wait between connection attempts.
    connect_retry_interval: Io.Duration = .fromMilliseconds(50),
    /// Child standard input, useful for descriptor-pinned QEMU block devices.
    stdin: std.process.SpawnOptions.StdIo = .ignore,
    stdout: std.process.SpawnOptions.StdIo = .inherit,
    stderr: std.process.SpawnOptions.StdIo = .inherit,
};

/// A `qemu-system-*` (or similar) process spawned by `spawnAndConnect`,
/// together with its connected QMP `Client`.
pub const Spawned = struct {
    allocator: std.mem.Allocator,
    io: Io,
    child: std.process.Child,
    client: *Client,
    qmp_socket_path: []const u8,

    /// Closes the QMP connection. Does *not* stop the child process --
    /// call `quit()` over `client` (before `deinit`) for a graceful
    /// shutdown, or `kill()` to force-terminate it.
    pub fn deinit(self: *Spawned) void {
        self.client.close();
        self.allocator.free(self.qmp_socket_path);
    }

    /// Forcibly terminates the child process and waits for it to exit.
    pub fn kill(self: *Spawned) void {
        self.child.kill(self.io);
    }

    /// Waits for the child process to exit (e.g. after sending it a QMP
    /// `quit` command over `client`).
    pub fn wait(self: *Spawned) !std.process.Child.Term {
        return self.child.wait(self.io);
    }

    /// Waits for the child while enforcing an absolute awake-clock deadline.
    pub fn waitUntil(
        self: *Spawned,
        deadline: Io.Timestamp,
    ) !std.process.Child.Term {
        const timeout_duration = try remainingDuration(self.io, deadline);
        const WaitResult = @typeInfo(
            @TypeOf(Spawned.wait),
        ).@"fn".return_type.?;
        const Selection = union(enum) {
            child: WaitResult,
            timeout: Io.Cancelable!void,
        };
        var buffer: [2]Selection = undefined;
        var select = Io.Select(Selection).init(self.io, &buffer);
        select.async(.child, Spawned.wait, .{self});
        select.async(
            .timeout,
            Io.sleep,
            .{ self.io, timeout_duration, .awake },
        );
        const selected = select.await() catch |err| {
            select.cancelDiscard();
            return err;
        };
        switch (selected) {
            .child => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => |result| {
                try result;
                select.cancelDiscard();
                return error.QmpTimedOut;
            },
        }
    }
};

fn remainingDuration(io: Io, deadline: Io.Timestamp) !Io.Duration {
    const now = Io.Clock.awake.now(io);
    if (now.nanoseconds >= deadline.nanoseconds) return error.QmpTimedOut;
    return .fromNanoseconds(deadline.nanoseconds - now.nanoseconds);
}

fn connectUnixUntil(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    deadline: Io.Timestamp,
) !*Client {
    const timeout_duration = try remainingDuration(io, deadline);
    const ConnectResult = @typeInfo(
        @TypeOf(Client.connectUnix),
    ).@"fn".return_type.?;
    const Selection = union(enum) {
        client: ConnectResult,
        timeout: Io.Cancelable!void,
    };
    var buffer: [2]Selection = undefined;
    var select = Io.Select(Selection).init(io, &buffer);
    select.async(
        .client,
        Client.connectUnix,
        .{ allocator, io, path },
    );
    select.async(
        .timeout,
        Io.sleep,
        .{ io, timeout_duration, .awake },
    );
    const selected = select.await() catch |err| {
        while (select.cancel()) |remaining| {
            switch (remaining) {
                .client => |client_result| {
                    if (client_result) |client| {
                        client.close();
                    } else |_| {}
                },
                .timeout => |timeout_result| timeout_result catch {},
            }
        }
        return err;
    };
    switch (selected) {
        .client => |result| {
            select.cancelDiscard();
            return result;
        },
        .timeout => |result| {
            try result;
            while (select.cancel()) |remaining| {
                switch (remaining) {
                    .client => |client_result| {
                        if (client_result) |client| {
                            client.close();
                        } else |_| {}
                    },
                    .timeout => |timeout_result| timeout_result catch {},
                }
            }
            return error.QmpTimedOut;
        },
    }
}

/// Launches `options.binary` with a generated (or explicit)
/// `-qmp unix:<path>,server=on,wait=off` argument, waits for the control
/// socket to appear and the greeting/capabilities handshake to succeed, and
/// returns the running child process together with a connected `Client`.
pub fn spawnAndConnect(allocator: std.mem.Allocator, io: Io, options: SpawnOptions) !Spawned {
    const sock_path = if (options.qmp_socket_path) |p|
        try allocator.dupe(u8, p)
    else
        try randomTempSocketPath(allocator, io);
    errdefer allocator.free(sock_path);

    const qmp_arg = try allocator.print("unix:{s},server=on,wait=off", .{sock_path});
    defer allocator.free(qmp_arg);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, options.binary);
    try argv.appendSlice(allocator, options.extra_args);
    try argv.append(allocator, "-qmp");
    try argv.append(allocator, qmp_arg);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = options.stdin,
        .stdout = options.stdout,
        .stderr = options.stderr,
    });
    errdefer child.kill(io);

    const deadline = Io.Clock.awake.now(io).addDuration(options.connect_timeout);
    const client = while (true) {
        break connectUnixUntil(
            allocator,
            io,
            sock_path,
            deadline,
        ) catch |err| {
            const now = Io.Clock.awake.now(io);
            if (err == error.QmpTimedOut or
                now.nanoseconds >= deadline.nanoseconds)
            {
                return error.QmpTimedOut;
            }
            const remaining = deadline.nanoseconds - now.nanoseconds;
            try Io.sleep(
                io,
                .fromNanoseconds(@min(
                    remaining,
                    options.connect_retry_interval.nanoseconds,
                )),
                .awake,
            );
            continue;
        };
    };

    return .{
        .allocator = allocator,
        .io = io,
        .child = child,
        .client = client,
        .qmp_socket_path = sock_path,
    };
}

fn randomTempSocketPath(allocator: std.mem.Allocator, io: Io) ![]u8 {
    var rand_bytes: [8]u8 = undefined;
    Io.random(io, &rand_bytes);
    const hex = std.fmt.bytesToHex(rand_bytes, .lower);
    return allocator.print("/tmp/qmp-{s}.sock", .{&hex});
}

test "readFrame: classifies the server greeting" {
    var r = Io.Reader.fixed(
        "{\"QMP\": {\"version\": {\"qemu\": {\"major\": 9}}, \"capabilities\": []}}\r\n",
    );
    var msg = try readFrame(std.testing.allocator, &r);
    defer switch (msg) {
        .greeting => |g| g.deinit(),
        .event => |e| e.deinit(),
        .reply => |rep| rep.deinit(),
    };
    try std.testing.expect(msg == .greeting);
    try std.testing.expect(msg.greeting.value.object.contains("QMP"));
}

test "readFrame: classifies a successful reply and extracts id" {
    var r = Io.Reader.fixed("{\"return\": {\"status\": \"running\"}, \"id\": 7}\r\n");
    var msg = try readFrame(std.testing.allocator, &r);
    defer msg.reply.deinit();
    try std.testing.expect(msg == .reply);
    try std.testing.expectEqual(@as(?u64, 7), msg.reply.id);
    try std.testing.expect(msg.reply.err == null);
    try std.testing.expectEqualStrings(
        "running",
        msg.reply.result.?.object.get("status").?.string,
    );
}

test "readFrame: classifies an error reply" {
    var r = Io.Reader.fixed(
        "{\"error\": {\"class\": \"GenericError\", \"desc\": \"bad\"}, \"id\": 3}\r\n",
    );
    var msg = try readFrame(std.testing.allocator, &r);
    defer msg.reply.deinit();
    try std.testing.expect(msg == .reply);
    try std.testing.expectEqual(@as(?u64, 3), msg.reply.id);
    try std.testing.expect(msg.reply.result == null);
    try std.testing.expectEqualStrings("GenericError", msg.reply.err.?.class);
    try std.testing.expectEqualStrings("bad", msg.reply.err.?.desc);
}

test "readFrame: classifies an event with timestamp" {
    var r = Io.Reader.fixed(
        "{\"event\": \"SHUTDOWN\", \"data\": {\"guest\": false}, " ++
            "\"timestamp\": {\"seconds\": 1234, \"microseconds\": 5678}}\r\n",
    );
    var msg = try readFrame(std.testing.allocator, &r);
    defer msg.event.deinit();
    try std.testing.expect(msg == .event);
    try std.testing.expectEqualStrings("SHUTDOWN", msg.event.name);
    try std.testing.expectEqual(@as(i64, 1234), msg.event.seconds);
    try std.testing.expectEqual(@as(i64, 5678), msg.event.microseconds);
    try std.testing.expectEqual(false, msg.event.data.?.object.get("guest").?.bool);
}

test "readFrame: event with no data and no timestamp still parses" {
    var r = Io.Reader.fixed("{\"event\": \"STOP\"}\r\n");
    var msg = try readFrame(std.testing.allocator, &r);
    defer msg.event.deinit();
    try std.testing.expect(msg == .event);
    try std.testing.expectEqualStrings("STOP", msg.event.name);
    try std.testing.expect(msg.event.data == null);
    try std.testing.expectEqual(@as(i64, -1), msg.event.seconds);
}

test "readFrame: rejects a non-object top-level value" {
    var r = Io.Reader.fixed("[1, 2, 3]\r\n");
    try std.testing.expectError(error.UnexpectedResponse, readFrame(std.testing.allocator, &r));
}

test "readFrame: rejects an object that is neither greeting, event, nor reply" {
    var r = Io.Reader.fixed("{\"foo\": \"bar\"}\r\n");
    try std.testing.expectError(error.UnexpectedResponse, readFrame(std.testing.allocator, &r));
}

test "writeCommand: encodes execute + arguments + id" {
    var buf: [256]u8 = undefined;
    var w = Io.Writer.fixed(&buf);

    var args: std.json.ObjectMap = .empty;
    defer args.deinit(std.testing.allocator);
    try args.put(std.testing.allocator, "device", .{ .string = "virtio0" });

    try writeCommand(&w, "device_add", .{ .object = args }, 42);

    const written = buf[0..w.end];
    try std.testing.expect(std.mem.endsWith(u8, written, "\n"));

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, written, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("device_add", obj.get("execute").?.string);
    try std.testing.expectEqual(@as(i64, 42), obj.get("id").?.integer);
    try std.testing.expectEqualStrings(
        "virtio0",
        obj.get("arguments").?.object.get("device").?.string,
    );
}

test "writeCommand: omits arguments when null" {
    var buf: [128]u8 = undefined;
    var w = Io.Writer.fixed(&buf);
    try writeCommand(&w, "query-status", null, 1);

    const written = buf[0..w.end];
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, written, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("query-status", obj.get("execute").?.string);
    try std.testing.expect(obj.get("arguments") == null);
}

test "spawnAndConnect bounds an exited child without a QMP socket" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    Io.Dir.cwd().access(std.testing.io, "/bin/false", .{
        .execute = true,
    }) catch return error.SkipZigTest;

    const started = Io.Clock.awake.now(std.testing.io);
    try std.testing.expectError(
        error.QmpTimedOut,
        spawnAndConnect(std.testing.allocator, std.testing.io, .{
            .binary = "/bin/false",
            .connect_timeout = .fromMilliseconds(100),
            .connect_retry_interval = .fromMilliseconds(10),
            .stdout = .ignore,
            .stderr = .ignore,
        }),
    );
    const elapsed = started.durationTo(
        Io.Clock.awake.now(std.testing.io),
    );
    try std.testing.expect(elapsed.nanoseconds < Io.Duration.fromSeconds(5).nanoseconds);
}

test "qapi: generated module fully type-checks" {
    comptime {
        @setEvalBranchQuota(100_000);
        for (@typeInfo(qapi).@"struct".decl_names) |name| {
            _ = @field(qapi, name);
        }
    }
}
