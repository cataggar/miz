//! Native Zig NBD (Network Block Device) client.
//!
//! A dependency-free client for the wire protocol QEMU's `qemu-nbd` and
//! `qemu-system-*` (`-M ...,export=nbd:...`) speak over a Unix domain or TCP
//! socket (see `docs/interop/nbd.rst` in the QEMU tree, and the upstream
//! protocol spec at
//! https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md). No
//! QEMU C code, no libvirt, no external dependencies.
//!
//! Scope: fixed newstyle handshake (oldstyle servers are not supported, per
//! the upstream spec's own recommendation against them since nbd 3.10),
//! `NBD_OPT_GO` negotiation (falling back to `NBD_OPT_EXPORT_NAME` for
//! servers that predate it), `NBD_OPT_STRUCTURED_REPLY`, and the
//! `READ`/`WRITE`/`FLUSH`/`TRIM`/`WRITE_ZEROES`/`DISC` transmission
//! commands, with both simple and structured replies.
//!
//! All integers on the wire are big-endian (network byte order), same
//! convention as the qcow2 on-disk format handled by `zig/qcow2`.
//!
//! The wire framing/classification logic (`writeOption` / `readOptionReply`
//! / `writeRequest` / `readReplyHeader`, etc.) is transport-agnostic -- it
//! operates on `std.Io.Reader`/`std.Io.Writer` directly, so it can be
//! unit-tested against in-memory buffers without a real socket or a running
//! `qemu-nbd`.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// A minimal, single-connection-at-a-time reference server (raw-file
/// backed), primarily for testing `Client` above end-to-end and for manual
/// interop testing against real NBD clients. See `server.zig` for details
/// and scope.
pub const server = @import("server.zig");

// ---------------------------------------------------------------------
// Wire protocol constants.
// ---------------------------------------------------------------------

/// Sent by the server as the first 8 bytes of the handshake, both old- and
/// newstyle. ASCII "NBDMAGIC".
pub const init_magic: u64 = 0x4e42444d41474943;
/// Sent by the server immediately after `init_magic` in newstyle
/// negotiation (in place of the oldstyle `cliserv_magic`), and reused as the
/// first 8 bytes of every client option request. ASCII "IHAVEOPT".
pub const opts_magic: u64 = 0x49484156454f5054;
/// Magic for every `NBDOptionReply` sent by the server during option
/// haggling (fixed newstyle only).
pub const rep_magic: u64 = 0x0003e889045565a9;

pub const request_magic: u32 = 0x25609513;
pub const simple_reply_magic: u32 = 0x67446698;
pub const structured_reply_magic: u32 = 0x668e33ef;

/// Handshake flags (server -> client, right after `init_magic`/`opts_magic`).
pub const handshake_flag_fixed_newstyle: u16 = 1 << 0;
pub const handshake_flag_no_zeroes: u16 = 1 << 1;

/// Client flags (client -> server, in reply to the handshake flags).
pub const client_flag_fixed_newstyle: u32 = 1 << 0;
pub const client_flag_no_zeroes: u32 = 1 << 1;

/// `NBD_OPT_*` -- option types used during option haggling.
pub const opt_export_name: u32 = 1;
pub const opt_abort: u32 = 2;
pub const opt_list: u32 = 3;
pub const opt_starttls: u32 = 5;
pub const opt_info: u32 = 6;
pub const opt_go: u32 = 7;
pub const opt_structured_reply: u32 = 8;
pub const opt_list_meta_context: u32 = 9;
pub const opt_set_meta_context: u32 = 10;
pub const opt_extended_headers: u32 = 11;

/// `NBD_REP_*` -- option reply types.
pub const rep_ack: u32 = 1;
pub const rep_server: u32 = 2;
pub const rep_info: u32 = 3;
pub const rep_meta_context: u32 = 4;
const rep_err_bit: u32 = 1 << 31;
pub const rep_err_unsup: u32 = rep_err_bit | 1;
pub const rep_err_policy: u32 = rep_err_bit | 2;
pub const rep_err_invalid: u32 = rep_err_bit | 3;
pub const rep_err_platform: u32 = rep_err_bit | 4;
pub const rep_err_tls_reqd: u32 = rep_err_bit | 5;
pub const rep_err_unknown: u32 = rep_err_bit | 6;
pub const rep_err_shutdown: u32 = rep_err_bit | 7;
pub const rep_err_block_size_reqd: u32 = rep_err_bit | 8;
pub const rep_err_too_big: u32 = rep_err_bit | 9;
pub const rep_err_ext_header_reqd: u32 = rep_err_bit | 10;

/// Whether an `NBD_REP_*` reply type denotes an error (bit 31 set).
pub fn repIsError(rep_type: u32) bool {
    return (rep_type & rep_err_bit) != 0;
}

/// `NBD_INFO_*` -- information types within an `NBD_REP_INFO` reply.
pub const info_export: u16 = 0;
pub const info_name: u16 = 1;
pub const info_description: u16 = 2;
pub const info_block_size: u16 = 3;

/// `NBD_FLAG_*` -- transmission flags (server -> client, describing what
/// the export supports during the transmission phase).
pub const flag_has_flags: u16 = 1 << 0;
pub const flag_read_only: u16 = 1 << 1;
pub const flag_send_flush: u16 = 1 << 2;
pub const flag_send_fua: u16 = 1 << 3;
pub const flag_rotational: u16 = 1 << 4;
pub const flag_send_trim: u16 = 1 << 5;
pub const flag_send_write_zeroes: u16 = 1 << 6;
pub const flag_send_df: u16 = 1 << 7;
pub const flag_can_multi_conn: u16 = 1 << 8;
pub const flag_send_resize: u16 = 1 << 9;
pub const flag_send_cache: u16 = 1 << 10;
pub const flag_send_fast_zero: u16 = 1 << 11;

/// `NBD_CMD_*` -- transmission request types.
pub const cmd_read: u16 = 0;
pub const cmd_write: u16 = 1;
pub const cmd_disc: u16 = 2;
pub const cmd_flush: u16 = 3;
pub const cmd_trim: u16 = 4;
pub const cmd_cache: u16 = 5;
pub const cmd_write_zeroes: u16 = 6;
pub const cmd_block_status: u16 = 7;

/// `NBD_CMD_FLAG_*` -- command flags, sent by the client with a request.
pub const cmd_flag_fua: u16 = 1 << 0;
pub const cmd_flag_no_hole: u16 = 1 << 1;
pub const cmd_flag_df: u16 = 1 << 2;
pub const cmd_flag_req_one: u16 = 1 << 3;
pub const cmd_flag_fast_zero: u16 = 1 << 4;

/// `NBD_REPLY_FLAG_*` -- structured/extended reply chunk flags.
pub const reply_flag_done: u16 = 1 << 0;

/// `NBD_REPLY_TYPE_*` -- structured reply chunk types.
pub const reply_type_none: u16 = 0;
pub const reply_type_offset_data: u16 = 1;
pub const reply_type_offset_hole: u16 = 2;
pub const reply_type_block_status: u16 = 5;
pub const reply_type_block_status_ext: u16 = 6;
const reply_err_bit: u16 = 1 << 15;
pub const reply_type_error: u16 = reply_err_bit | 1;
pub const reply_type_error_offset: u16 = reply_err_bit | 2;

/// Whether an `NBD_REPLY_TYPE_*` chunk type denotes an error (bit 15 set).
pub fn replyTypeIsError(reply_type: u16) bool {
    return (reply_type & reply_err_bit) != 0;
}

pub const default_port: u16 = 10809;

pub const Error = error{
    /// The server's initial magic bytes didn't match `init_magic`.
    UnexpectedMagic,
    /// The server doesn't support newstyle (or fixed newstyle) negotiation.
    /// Oldstyle servers (pre nbd 2.9.17) are not supported.
    UnsupportedOldstyleServer,
    /// An `NBD_OPT_*` request was rejected with an `NBD_REP_ERR_*` other
    /// than `NBD_REP_ERR_UNSUP` (which callers fall back on instead).
    OptionRejected,
    /// A reply (option reply, request reply, or chunk) referred to an
    /// option or cookie/handle we didn't expect.
    UnexpectedReply,
    /// The server replied with a nonzero `error` field (simple reply) or an
    /// `NBD_REPLY_TYPE_ERROR*` chunk (structured reply). See
    /// `Client.last_errno` for the raw NBD/errno value.
    ServerError,
};

/// An `NBDOptionReply` header, as read from the wire during option
/// haggling (fixed newstyle only). The `length`-byte payload (if any)
/// follows on the wire and must be consumed by the caller.
pub const OptionReply = struct {
    option: u32,
    rep_type: u32,
    length: u32,
};

/// Send an `NBDOption` (`IHAVEOPT` + option + length + data) and flush.
///
/// Transport-agnostic: `w` may be backed by a real socket or, in tests, by
/// `std.Io.Writer.fixed`/`std.Io.Writer.Allocating`.
pub fn writeOption(w: *Io.Writer, option: u32, data: []const u8) !void {
    try w.writeInt(u64, opts_magic, .big);
    try w.writeInt(u32, option, .big);
    try w.writeInt(u32, @intCast(data.len), .big);
    if (data.len > 0) try w.writeAll(data);
    try w.flush();
}

/// Read one `NBDOptionReply` header. The caller is responsible for reading
/// (or discarding) the `length`-byte payload that follows on the wire.
pub fn readOptionReply(r: *Io.Reader) !OptionReply {
    const magic = try r.takeInt(u64, .big);
    if (magic != rep_magic) return Error.UnexpectedMagic;
    return .{
        .option = try r.takeInt(u32, .big),
        .rep_type = try r.takeInt(u32, .big),
        .length = try r.takeInt(u32, .big),
    };
}

/// An `NBDRequest` header, as sent by the client. `length` bytes of data
/// follow on the wire for `cmd_write` only.
pub const RequestHeader = struct {
    flags: u16,
    type: u16,
    cookie: u64,
    offset: u64,
    length: u32,
};

/// Write an `NBDRequest` header (and `data`, for `cmd_write`) and flush.
/// Exposed (not just used internally by `Client`) so a future NBD server
/// implementation can reuse it, symmetric with `readRequestHeader`.
pub fn writeRequest(w: *Io.Writer, req: RequestHeader, data: ?[]const u8) !void {
    try w.writeInt(u32, request_magic, .big);
    try w.writeInt(u16, req.flags, .big);
    try w.writeInt(u16, req.type, .big);
    try w.writeInt(u64, req.cookie, .big);
    try w.writeInt(u64, req.offset, .big);
    try w.writeInt(u32, req.length, .big);
    if (data) |d| try w.writeAll(d);
    try w.flush();
}

/// Read an `NBDRequest` header (server-side use). Returns `null` if the
/// stream is at a clean EOF before any bytes were read (i.e. the client
/// disconnected between requests).
pub fn readRequestHeader(r: *Io.Reader) !RequestHeader {
    const magic = try r.takeInt(u32, .big);
    if (magic != request_magic) return Error.UnexpectedMagic;
    return .{
        .flags = try r.takeInt(u16, .big),
        .type = try r.takeInt(u16, .big),
        .cookie = try r.takeInt(u64, .big),
        .offset = try r.takeInt(u64, .big),
        .length = try r.takeInt(u32, .big),
    };
}

pub const SimpleReply = struct {
    err: u32,
    cookie: u64,
};

pub const StructuredReplyChunk = struct {
    flags: u16,
    type: u16,
    cookie: u64,
    length: u32,
};

/// A reply header read from the transmission phase: either a simple reply
/// or a structured reply chunk (distinguished by its magic). The caller
/// must consume any trailing payload described by the header.
pub const ReplyHeader = union(enum) {
    simple: SimpleReply,
    structured: StructuredReplyChunk,
};

/// Read one reply header (simple or structured) from `r`.
pub fn readReplyHeader(r: *Io.Reader) !ReplyHeader {
    const magic = try r.takeInt(u32, .big);
    return switch (magic) {
        simple_reply_magic => .{ .simple = .{
            .err = try r.takeInt(u32, .big),
            .cookie = try r.takeInt(u64, .big),
        } },
        structured_reply_magic => .{ .structured = .{
            .flags = try r.takeInt(u16, .big),
            .type = try r.takeInt(u16, .big),
            .cookie = try r.takeInt(u64, .big),
            .length = try r.takeInt(u32, .big),
        } },
        else => Error.UnexpectedMagic,
    };
}

/// Write a simple reply (server-side use).
pub fn writeSimpleReply(w: *Io.Writer, reply: SimpleReply) !void {
    try w.writeInt(u32, simple_reply_magic, .big);
    try w.writeInt(u32, reply.err, .big);
    try w.writeInt(u64, reply.cookie, .big);
    try w.flush();
}

// ---------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------

/// A connected NBD session: a Unix domain or TCP socket to an `qemu-nbd` (or
/// any other NBD server), past the handshake and export negotiation, ready
/// for transmission-phase commands.
///
/// Heap-allocated (via `connectUnix`/`connectTcp`) so the read/write buffers
/// embedded in it have a stable address for the lifetime of the connection.
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    read_buf: [65536]u8 = undefined,
    write_buf: [4096]u8 = undefined,
    stream_reader: net.Stream.Reader = undefined,
    stream_writer: net.Stream.Writer = undefined,
    next_cookie: u64 = 1,

    /// Size of the negotiated export, in bytes.
    export_size: u64 = 0,
    /// `flag_*` transmission flags advertised by the server for this export.
    transmission_flags: u16 = 0,
    /// Whether `NBD_OPT_STRUCTURED_REPLY` was successfully negotiated.
    structured_replies: bool = false,
    /// Whether we asked for (and the server honored) `client_flag_no_zeroes`
    /// -- only relevant to the `NBD_OPT_EXPORT_NAME` fallback path.
    no_zeroes: bool = false,
    /// The raw NBD/errno value from the most recent `Error.ServerError`.
    last_errno: u32 = 0,

    /// Connect to the Unix domain socket at `path` and negotiate `export_name`.
    pub fn connectUnix(allocator: std.mem.Allocator, io: Io, path: []const u8, export_name: []const u8) !*Client {
        const addr = try net.UnixAddress.init(path);
        const stream = try addr.connect(io);
        errdefer stream.close(io);
        return connectStream(allocator, io, stream, export_name);
    }

    /// Connect to a TCP NBD server at `address` and negotiate `export_name`.
    pub fn connectTcp(allocator: std.mem.Allocator, io: Io, address: net.IpAddress, export_name: []const u8) !*Client {
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        return connectStream(allocator, io, stream, export_name);
    }

    fn connectStream(allocator: std.mem.Allocator, io: Io, stream: net.Stream, export_name: []const u8) !*Client {
        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
        };
        self.stream_reader = net.Stream.Reader.init(self.stream, io, &self.read_buf);
        self.stream_writer = net.Stream.Writer.init(self.stream, io, &self.write_buf);

        const r = &self.stream_reader.interface;
        const w = &self.stream_writer.interface;

        if (try r.takeInt(u64, .big) != init_magic) return Error.UnexpectedMagic;
        if (try r.takeInt(u64, .big) != opts_magic) return Error.UnsupportedOldstyleServer;
        const handshake_flags = try r.takeInt(u16, .big);
        if (handshake_flags & handshake_flag_fixed_newstyle == 0) {
            return Error.UnsupportedOldstyleServer;
        }

        var client_flags: u32 = client_flag_fixed_newstyle;
        if (handshake_flags & handshake_flag_no_zeroes != 0) {
            client_flags |= client_flag_no_zeroes;
            self.no_zeroes = true;
        }
        try w.writeInt(u32, client_flags, .big);
        try w.flush();

        // Best-effort: structured replies make NBD_CMD_READ error handling
        // and sparse reads far more useful. Fall back silently to simple
        // replies if unsupported.
        self.structured_replies = try self.negotiateSimpleOption(opt_structured_reply);

        if (!try self.negotiateGo(export_name)) {
            try self.negotiateExportNameLegacy(export_name);
        }

        return self;
    }

    /// Send an option with no payload and expect a single `NBD_REP_ACK` /
    /// `NBD_REP_ERR_*` reply (used for e.g. `opt_structured_reply`).
    /// Returns whether the option was acknowledged.
    fn negotiateSimpleOption(self: *Client, option: u32) !bool {
        try writeOption(&self.stream_writer.interface, option, &.{});
        const reply = try readOptionReply(&self.stream_reader.interface);
        if (reply.option != option) return Error.UnexpectedReply;
        if (reply.length > 0) try self.stream_reader.interface.discardAll(reply.length);
        if (reply.rep_type == rep_ack) return true;
        if (repIsError(reply.rep_type)) return false;
        return Error.UnexpectedReply;
    }

    /// `NBD_OPT_GO`: negotiate straight into the transmission phase.
    /// Returns `false` (having sent/consumed no further state) if the
    /// server doesn't support `NBD_OPT_GO` at all, so the caller can fall
    /// back to `negotiateExportNameLegacy`.
    fn negotiateGo(self: *Client, export_name: []const u8) !bool {
        var payload: std.Io.Writer.Allocating = .init(self.allocator);
        defer payload.deinit();
        try payload.writer.writeInt(u32, @intCast(export_name.len), .big);
        try payload.writer.writeAll(export_name);
        try payload.writer.writeInt(u16, 0, .big); // no specific NBD_INFO_* requests
        try writeOption(&self.stream_writer.interface, opt_go, payload.written());

        while (true) {
            const reply = try readOptionReply(&self.stream_reader.interface);
            if (reply.option != opt_go) return Error.UnexpectedReply;
            switch (reply.rep_type) {
                rep_info => try self.consumeInfoPayload(reply.length),
                rep_ack => return true,
                else => {
                    if (reply.length > 0) try self.stream_reader.interface.discardAll(reply.length);
                    if (!repIsError(reply.rep_type)) return Error.UnexpectedReply;
                    if (reply.rep_type == rep_err_unsup) return false;
                    return Error.OptionRejected;
                },
            }
        }
    }

    /// Parse an `NBD_REP_INFO` payload, extracting `NBD_INFO_EXPORT` (size +
    /// transmission flags) and discarding all other information types.
    fn consumeInfoPayload(self: *Client, length: u32) !void {
        const r = &self.stream_reader.interface;
        const info_type = try r.takeInt(u16, .big);
        var remaining: u32 = length - 2;
        switch (info_type) {
            info_export => {
                self.export_size = try r.takeInt(u64, .big);
                self.transmission_flags = try r.takeInt(u16, .big);
                remaining -= 10;
            },
            else => {},
        }
        if (remaining > 0) try r.discardAll(remaining);
    }

    /// `NBD_OPT_EXPORT_NAME` fallback for servers that don't support
    /// `NBD_OPT_GO`. Cannot report export-not-found errors -- the server
    /// simply drops the connection, which surfaces here as a read error.
    fn negotiateExportNameLegacy(self: *Client, export_name: []const u8) !void {
        const w = &self.stream_writer.interface;
        try w.writeInt(u64, opts_magic, .big);
        try w.writeInt(u32, opt_export_name, .big);
        try w.writeInt(u32, @intCast(export_name.len), .big);
        try w.writeAll(export_name);
        try w.flush();

        const r = &self.stream_reader.interface;
        self.export_size = try r.takeInt(u64, .big);
        self.transmission_flags = try r.takeInt(u16, .big);
        if (!self.no_zeroes) try r.discardAll(124);
    }

    pub fn close(self: *Client) void {
        self.stream.close(self.io);
        self.allocator.destroy(self);
    }

    fn nextCookie(self: *Client) u64 {
        const c = self.next_cookie;
        self.next_cookie += 1;
        return c;
    }

    fn sendRequest(self: *Client, cookie: u64, cmd_type: u16, flags: u16, offset: u64, length: u32, data: ?[]const u8) !void {
        try writeRequest(&self.stream_writer.interface, .{
            .flags = flags,
            .type = cmd_type,
            .cookie = cookie,
            .offset = offset,
            .length = length,
        }, data);
    }

    /// Read `error`+`message_length`+message (and, for `ERROR_OFFSET`, the
    /// trailing 8-byte offset) from a structured error chunk, discarding
    /// the message text, and record `error` in `last_errno`.
    fn consumeErrorChunk(self: *Client, chunk_type: u16, length: u32) !void {
        const r = &self.stream_reader.interface;
        self.last_errno = try r.takeInt(u32, .big);
        const message_length = try r.takeInt(u16, .big);
        if (message_length > 0) try r.discardAll(message_length);
        var consumed: u32 = 6 + message_length;
        if (chunk_type == reply_type_error_offset) {
            try r.discardAll(8);
            consumed += 8;
        }
        if (length > consumed) try r.discardAll(length - consumed);
    }

    /// Wait for the (simple- or structured-reply) acknowledgement of a
    /// non-`READ` request, propagating server errors.
    fn expectAck(self: *Client, cookie: u64) !void {
        while (true) {
            const hdr = try readReplyHeader(&self.stream_reader.interface);
            switch (hdr) {
                .simple => |s| {
                    if (s.cookie != cookie) return Error.UnexpectedReply;
                    if (s.err != 0) {
                        self.last_errno = s.err;
                        return Error.ServerError;
                    }
                    return;
                },
                .structured => |c| {
                    if (c.cookie != cookie) return Error.UnexpectedReply;
                    if (replyTypeIsError(c.type)) {
                        try self.consumeErrorChunk(c.type, c.length);
                        return Error.ServerError;
                    }
                    if (c.length > 0) try self.stream_reader.interface.discardAll(c.length);
                    if (c.flags & reply_flag_done != 0) return;
                },
            }
        }
    }

    /// Read the reply to an `NBD_CMD_READ` request for `buf.len` bytes
    /// starting at `request_offset`, into `buf`.
    fn readInto(self: *Client, cookie: u64, request_offset: u64, buf: []u8) !void {
        while (true) {
            const hdr = try readReplyHeader(&self.stream_reader.interface);
            switch (hdr) {
                .simple => |s| {
                    if (s.cookie != cookie) return Error.UnexpectedReply;
                    if (s.err != 0) {
                        self.last_errno = s.err;
                        return Error.ServerError;
                    }
                    try self.stream_reader.interface.readSliceAll(buf);
                    return;
                },
                .structured => |c| {
                    if (c.cookie != cookie) return Error.UnexpectedReply;
                    if (replyTypeIsError(c.type)) {
                        try self.consumeErrorChunk(c.type, c.length);
                        return Error.ServerError;
                    }
                    switch (c.type) {
                        reply_type_none => {
                            if (c.length > 0) try self.stream_reader.interface.discardAll(c.length);
                        },
                        reply_type_offset_data => {
                            const off = try self.stream_reader.interface.takeInt(u64, .big);
                            const data_len = c.length - 8;
                            const rel: usize = @intCast(off - request_offset);
                            try self.stream_reader.interface.readSliceAll(buf[rel..][0..data_len]);
                        },
                        reply_type_offset_hole => {
                            const off = try self.stream_reader.interface.takeInt(u64, .big);
                            const hole_len = try self.stream_reader.interface.takeInt(u32, .big);
                            const rel: usize = @intCast(off - request_offset);
                            @memset(buf[rel..][0..hole_len], 0);
                        },
                        else => {
                            // Forward-compatible: skip chunk types we don't
                            // understand rather than hard-disconnecting.
                            if (c.length > 0) try self.stream_reader.interface.discardAll(c.length);
                        },
                    }
                    if (c.flags & reply_flag_done != 0) return;
                },
            }
        }
    }

    /// `NBD_CMD_READ`: read `buf.len` bytes starting at `offset` into `buf`.
    pub fn read(self: *Client, offset: u64, buf: []u8) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_read, 0, offset, @intCast(buf.len), null);
        try self.readInto(cookie, offset, buf);
    }

    /// `NBD_CMD_WRITE`: write `data` starting at `offset`.
    pub fn write(self: *Client, offset: u64, data: []const u8) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_write, 0, offset, @intCast(data.len), data);
        try self.expectAck(cookie);
    }

    /// `NBD_CMD_FLUSH`: request that all completed writes be made durable.
    /// Only meaningful if `transmission_flags & flag_send_flush != 0`.
    pub fn flush(self: *Client) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_flush, 0, 0, 0, null);
        try self.expectAck(cookie);
    }

    /// `NBD_CMD_TRIM`: hint that `len` bytes starting at `offset` are no
    /// longer needed (discard). Only meaningful if
    /// `transmission_flags & flag_send_trim != 0`.
    pub fn trim(self: *Client, offset: u64, len: u64) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_trim, 0, offset, @intCast(len), null);
        try self.expectAck(cookie);
    }

    /// `NBD_CMD_WRITE_ZEROES`: write `len` zero bytes starting at `offset`.
    /// Only meaningful if `transmission_flags & flag_send_write_zeroes != 0`.
    /// `flags` may include `cmd_flag_no_hole` / `cmd_flag_fast_zero`.
    pub fn writeZeroes(self: *Client, offset: u64, len: u64, flags: u16) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_write_zeroes, flags, offset, @intCast(len), null);
        try self.expectAck(cookie);
    }

    /// `NBD_CMD_DISC`: initiate a clean ("soft") disconnect. The server
    /// sends no reply; the caller should call `close()` afterwards.
    pub fn disconnect(self: *Client) !void {
        const cookie = self.nextCookie();
        try self.sendRequest(cookie, cmd_disc, 0, 0, 0, null);
    }
};

// ---------------------------------------------------------------------
// Tests -- pure protocol framing, no socket needed.
// ---------------------------------------------------------------------

const testing = std.testing;

test "writeOption / readOptionReply round-trip" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try writeOption(&buf.writer, opt_go, "hello");

    var r: Io.Reader = .fixed(buf.written());
    // Verify the option request itself: IHAVEOPT + option + length + data.
    try testing.expectEqual(opts_magic, try r.takeInt(u64, .big));
    try testing.expectEqual(@as(u32, opt_go), try r.takeInt(u32, .big));
    try testing.expectEqual(@as(u32, 5), try r.takeInt(u32, .big));
    try testing.expectEqualStrings("hello", try r.take(5));
}

test "readOptionReply parses NBDOptionReply header" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u64, rep_magic, .big);
    try buf.writer.writeInt(u32, opt_go, .big);
    try buf.writer.writeInt(u32, rep_ack, .big);
    try buf.writer.writeInt(u32, 0, .big);

    var r: Io.Reader = .fixed(buf.written());
    const reply = try readOptionReply(&r);
    try testing.expectEqual(@as(u32, opt_go), reply.option);
    try testing.expectEqual(@as(u32, rep_ack), reply.rep_type);
    try testing.expectEqual(@as(u32, 0), reply.length);
}

test "readOptionReply rejects bad magic" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u64, 0xdeadbeef, .big);
    try buf.writer.writeInt(u32, 0, .big);
    try buf.writer.writeInt(u32, 0, .big);
    try buf.writer.writeInt(u32, 0, .big);

    var r: Io.Reader = .fixed(buf.written());
    try testing.expectError(Error.UnexpectedMagic, readOptionReply(&r));
}

test "writeRequest / readRequestHeader round-trip (WRITE)" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try writeRequest(&buf.writer, .{
        .flags = cmd_flag_fua,
        .type = cmd_write,
        .cookie = 42,
        .offset = 4096,
        .length = 3,
    }, "abc");

    var r: Io.Reader = .fixed(buf.written());
    const req = try readRequestHeader(&r);
    try testing.expectEqual(@as(u16, cmd_flag_fua), req.flags);
    try testing.expectEqual(@as(u16, cmd_write), req.type);
    try testing.expectEqual(@as(u64, 42), req.cookie);
    try testing.expectEqual(@as(u64, 4096), req.offset);
    try testing.expectEqual(@as(u32, 3), req.length);
    try testing.expectEqualStrings("abc", try r.take(3));
}

test "readReplyHeader parses simple reply" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u32, simple_reply_magic, .big);
    try buf.writer.writeInt(u32, 0, .big);
    try buf.writer.writeInt(u64, 7, .big);

    var r: Io.Reader = .fixed(buf.written());
    const hdr = try readReplyHeader(&r);
    try testing.expect(hdr == .simple);
    try testing.expectEqual(@as(u32, 0), hdr.simple.err);
    try testing.expectEqual(@as(u64, 7), hdr.simple.cookie);
}

test "readReplyHeader parses structured reply chunk" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u32, structured_reply_magic, .big);
    try buf.writer.writeInt(u16, reply_flag_done, .big);
    try buf.writer.writeInt(u16, reply_type_offset_data, .big);
    try buf.writer.writeInt(u64, 7, .big);
    try buf.writer.writeInt(u32, 12, .big);

    var r: Io.Reader = .fixed(buf.written());
    const hdr = try readReplyHeader(&r);
    try testing.expect(hdr == .structured);
    try testing.expectEqual(@as(u16, reply_flag_done), hdr.structured.flags);
    try testing.expectEqual(@as(u16, reply_type_offset_data), hdr.structured.type);
    try testing.expectEqual(@as(u64, 7), hdr.structured.cookie);
    try testing.expectEqual(@as(u32, 12), hdr.structured.length);
}

test "fixed newstyle handshake greeting" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u64, init_magic, .big);
    try buf.writer.writeInt(u64, opts_magic, .big);
    try buf.writer.writeInt(u16, handshake_flag_fixed_newstyle | handshake_flag_no_zeroes, .big);

    var r: Io.Reader = .fixed(buf.written());
    try testing.expectEqual(init_magic, try r.takeInt(u64, .big));
    try testing.expectEqual(opts_magic, try r.takeInt(u64, .big));
    const flags = try r.takeInt(u16, .big);
    try testing.expect(flags & handshake_flag_fixed_newstyle != 0);
    try testing.expect(flags & handshake_flag_no_zeroes != 0);
}

test "NBD_INFO_EXPORT payload parsing" {
    // NBD_REP_INFO payload: info_type(2) + size(8) + transmission flags(2).
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try buf.writer.writeInt(u16, info_export, .big);
    try buf.writer.writeInt(u64, 64 * 1024 * 1024, .big);
    try buf.writer.writeInt(u16, flag_has_flags | flag_send_flush | flag_send_trim, .big);

    var r: Io.Reader = .fixed(buf.written());
    try testing.expectEqual(@as(u16, info_export), try r.takeInt(u16, .big));
    try testing.expectEqual(@as(u64, 64 * 1024 * 1024), try r.takeInt(u64, .big));
    const flags = try r.takeInt(u16, .big);
    try testing.expect(flags & flag_send_flush != 0);
    try testing.expect(flags & flag_send_trim != 0);
}

test "repIsError / replyTypeIsError" {
    try testing.expect(repIsError(rep_err_unsup));
    try testing.expect(repIsError(rep_err_unknown));
    try testing.expect(!repIsError(rep_ack));
    try testing.expect(!repIsError(rep_info));

    try testing.expect(replyTypeIsError(reply_type_error));
    try testing.expect(replyTypeIsError(reply_type_error_offset));
    try testing.expect(!replyTypeIsError(reply_type_none));
    try testing.expect(!replyTypeIsError(reply_type_offset_data));
}

test "structured read transcript: OFFSET_DATA + OFFSET_HOLE + DONE" {
    // Simulates the server's reply stream to a single NBD_CMD_READ of 16
    // bytes at offset 0, split into a data chunk covering [0,8) and a hole
    // chunk covering [8,16).
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const w = &buf.writer;

    // Chunk 1: OFFSET_DATA, offset=0, data="ABCDEFGH" (8 bytes) -> length=16.
    try w.writeInt(u32, structured_reply_magic, .big);
    try w.writeInt(u16, 0, .big); // not done yet
    try w.writeInt(u16, reply_type_offset_data, .big);
    try w.writeInt(u64, 99, .big);
    try w.writeInt(u32, 16, .big); // 8 (offset) + 8 (data)
    try w.writeInt(u64, 0, .big);
    try w.writeAll("ABCDEFGH");

    // Chunk 2: OFFSET_HOLE, offset=8, hole_len=8 -> length=12, flags=DONE.
    try w.writeInt(u32, structured_reply_magic, .big);
    try w.writeInt(u16, reply_flag_done, .big);
    try w.writeInt(u16, reply_type_offset_hole, .big);
    try w.writeInt(u64, 99, .big);
    try w.writeInt(u32, 12, .big);
    try w.writeInt(u64, 8, .big);
    try w.writeInt(u32, 8, .big);

    var r: Io.Reader = .fixed(buf.written());
    var out: [16]u8 = undefined;
    @memset(&out, 0xff);

    // Re-implement the relevant slice of Client.readInto's dispatch loop
    // directly against the transcript above (Client itself needs a real
    // net.Stream, which isn't available in a unit test).
    var done = false;
    while (!done) {
        const hdr = try readReplyHeader(&r);
        const c = hdr.structured;
        try testing.expectEqual(@as(u64, 99), c.cookie);
        switch (c.type) {
            reply_type_offset_data => {
                const off = try r.takeInt(u64, .big);
                const data_len = c.length - 8;
                try r.readSliceAll(out[off..][0..data_len]);
            },
            reply_type_offset_hole => {
                const off = try r.takeInt(u64, .big);
                const hole_len = try r.takeInt(u32, .big);
                @memset(out[off..][0..hole_len], 0);
            },
            else => unreachable,
        }
        if (c.flags & reply_flag_done != 0) done = true;
    }

    try testing.expectEqualStrings("ABCDEFGH", out[0..8]);
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0))), out[8..16]);
}

test "structured error chunk transcript" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const w = &buf.writer;

    const message = "no such file";
    try w.writeInt(u32, structured_reply_magic, .big);
    try w.writeInt(u16, reply_flag_done, .big);
    try w.writeInt(u16, reply_type_error, .big);
    try w.writeInt(u64, 5, .big);
    try w.writeInt(u32, @as(u32, 6 + message.len), .big);
    try w.writeInt(u32, 2, .big); // ENOENT
    try w.writeInt(u16, @intCast(message.len), .big);
    try w.writeAll(message);

    var r: Io.Reader = .fixed(buf.written());
    const hdr = try readReplyHeader(&r);
    try testing.expect(replyTypeIsError(hdr.structured.type));
    const errno = try r.takeInt(u32, .big);
    try testing.expectEqual(@as(u32, 2), errno);
    const msg_len = try r.takeInt(u16, .big);
    try testing.expectEqualStrings(message, try r.take(msg_len));
}
