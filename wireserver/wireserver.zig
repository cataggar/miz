//! Minimal, native Zig client for the subset of the Azure WireServer "goal
//! state" protocol needed to provision a VM: protocol version negotiation,
//! fetching the goal state (incarnation/container id/role instance id), and
//! reporting instance health back to the WireServer. This is a building
//! block for `azagent` (see github.com/cataggar/miz issue #112); the
//! HostGAPlugin/vmSettings fast-track path, IMDS, extension config/manifest
//! handling, and client-certificate-authenticated endpoints are explicitly
//! out of scope (see issue #111).
//!
//! Reference: `azurelinuxagent/common/protocol/wire.py` and `goal_state.py`
//! (Microsoft Azure Linux Agent, analyzed at /work/WALinuxAgent during
//! planning).
const std = @import("std");

pub const xml = @import("xml.zig");

/// Well-known WireServer address, reachable only from inside the guest VM.
/// Matches upstream's fallback in `azurelinuxagent/common/utils/networkutil.py`.
pub const default_endpoint = "168.63.129.16";

/// The wire protocol version this client speaks. Matches upstream's
/// `PROTOCOL_VERSION` in `wire.py`.
pub const protocol_version = "2012-11-30";

pub const agent_name = "azagent";

pub const ParseError = xml.ParseError || error{MissingField};

/// Parsed `GET /?comp=versions` response (`Versions.xml`).
pub const VersionInfo = struct {
    doc: []const u8,

    pub fn parse(xml_text: []const u8) ParseError!VersionInfo {
        if (xml.findElement(xml_text, "Preferred") == null) return error.MissingField;
        return .{ .doc = xml_text };
    }

    /// The Fabric-preferred protocol version, e.g. "2012-11-30".
    pub fn preferred(self: VersionInfo) ?[]const u8 {
        const block = xml.findElement(self.doc, "Preferred") orelse return null;
        return xml.findElement(block, "Version");
    }

    /// True if `version` appears in the `<Supported>` list.
    pub fn isSupported(self: VersionInfo, version: []const u8) bool {
        const block = xml.findElement(self.doc, "Supported") orelse return false;
        var it = xml.ElementIterator.init(block, "Version");
        while (it.next()) |v| {
            if (std.mem.eql(u8, v, version)) return true;
        }
        return false;
    }
};

/// The minimal subset of `GET /machine/?comp=goalstate` needed to provision
/// a VM and report health: the incarnation (needed to echo back in the
/// health report) and the container/role-instance IDs (needed to build the
/// health report's URI path and body). Kept as borrowed slices into the
/// original document, matching `xml.zig`'s zero-copy design.
pub const GoalState = struct {
    incarnation: []const u8,
    container_id: []const u8,
    role_instance_id: []const u8,

    pub fn parse(xml_text: []const u8) ParseError!GoalState {
        const incarnation = xml.findElement(xml_text, "Incarnation") orelse return error.MissingField;
        const container_id = xml.findElement(xml_text, "ContainerId") orelse return error.MissingField;
        const role_instance_id = xml.findElement(xml_text, "InstanceId") orelse return error.MissingField;
        return .{
            .incarnation = incarnation,
            .container_id = container_id,
            .role_instance_id = role_instance_id,
        };
    }
};

/// Matches the `State` values upstream's `ga/exthandlers.py` reports
/// ("Ready" / "NotReady").
pub const HealthState = enum {
    ready,
    not_ready,

    pub fn asString(self: HealthState) []const u8 {
        return switch (self) {
            .ready => "Ready",
            .not_ready => "NotReady",
        };
    }
};

/// Describes a health/status report to send back to the WireServer via
/// `POST /machine?comp=health`, matching upstream's `_build_health_report`.
pub const HealthReport = struct {
    incarnation: []const u8,
    container_id: []const u8,
    role_instance_id: []const u8,
    state: HealthState,
    /// Only meaningful (and only emitted) when `state == .not_ready`.
    sub_status: ?[]const u8 = null,
    description: ?[]const u8 = null,
};

/// Builds the `<Health>` XML POST body for `report`. `sub_status` and
/// `description` are XML-escaped (`&`, `<`, `>` only, matching upstream's
/// use of `xml.sax.saxutils.escape`).
pub fn buildHealthReportXml(allocator: std.mem.Allocator, report: HealthReport) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, 256);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>" ++
            "<Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">" ++
            "<GoalStateIncarnation>{s}</GoalStateIncarnation>" ++
            "<Container><ContainerId>{s}</ContainerId>" ++
            "<RoleInstanceList><Role><InstanceId>{s}</InstanceId>" ++
            "<Health><State>{s}</State>",
        .{ report.incarnation, report.container_id, report.role_instance_id, report.state.asString() },
    );

    if (report.sub_status) |sub_status| {
        const escaped_sub_status = try xml.escapeAlloc(allocator, sub_status);
        defer allocator.free(escaped_sub_status);
        const escaped_description = if (report.description) |d| try xml.escapeAlloc(allocator, d) else "";
        defer if (report.description != null) allocator.free(escaped_description);

        try w.print(
            "<Details><SubStatus>{s}</SubStatus><Description>{s}</Description></Details>",
            .{ escaped_sub_status, escaped_description },
        );
    }

    try w.writeAll("</Health></Role></RoleInstanceList></Container></Health>");

    return out.toOwnedSlice();
}

test "VersionInfo.parse extracts preferred and checks supported versions" {
    const doc =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<Versions>
        \\  <Preferred>
        \\    <Version>2012-11-30</Version>
        \\  </Preferred>
        \\  <Supported>
        \\    <Version>2010-12-15</Version>
        \\    <Version>2012-11-30</Version>
        \\  </Supported>
        \\</Versions>
    ;
    const info = try VersionInfo.parse(doc);
    try std.testing.expectEqualStrings("2012-11-30", info.preferred().?);
    try std.testing.expect(info.isSupported("2012-11-30"));
    try std.testing.expect(info.isSupported("2010-12-15"));
    try std.testing.expect(!info.isSupported("1999-01-01"));
}

test "VersionInfo.parse rejects a document with no Preferred element" {
    try std.testing.expectError(error.MissingField, VersionInfo.parse("<Versions></Versions>"));
}

test "GoalState.parse extracts incarnation, container id, and role instance id" {
    const doc =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
        \\   <Version>2012-11-30</Version>
        \\   <Incarnation>3</Incarnation>
        \\   <Container>
        \\     <ContainerId>11111111-2222-3333-4444-555555555555</ContainerId>
        \\     <RoleInstanceList>
        \\       <RoleInstance>
        \\         <InstanceId>66666666-7777-8888-9999-aaaaaaaaaaaa.MachineRole_IN_0</InstanceId>
        \\         <State>Started</State>
        \\       </RoleInstance>
        \\     </RoleInstanceList>
        \\   </Container>
        \\ </GoalState>
    ;
    const gs = try GoalState.parse(doc);
    try std.testing.expectEqualStrings("3", gs.incarnation);
    try std.testing.expectEqualStrings("11111111-2222-3333-4444-555555555555", gs.container_id);
    try std.testing.expectEqualStrings("66666666-7777-8888-9999-aaaaaaaaaaaa.MachineRole_IN_0", gs.role_instance_id);
}

test "GoalState.parse fails when a required field is missing" {
    try std.testing.expectError(error.MissingField, GoalState.parse("<GoalState><Incarnation>1</Incarnation></GoalState>"));
}

test "buildHealthReportXml emits a Ready report with no Details" {
    const allocator = std.testing.allocator;
    const body = try buildHealthReportXml(allocator, .{
        .incarnation = "3",
        .container_id = "c-id",
        .role_instance_id = "r-id",
        .state = .ready,
    });
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "<GoalStateIncarnation>3</GoalStateIncarnation>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<ContainerId>c-id</ContainerId>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<InstanceId>r-id</InstanceId>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<State>Ready</State>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<Details>") == null);
}

test "buildHealthReportXml emits an escaped NotReady report with Details" {
    const allocator = std.testing.allocator;
    const body = try buildHealthReportXml(allocator, .{
        .incarnation = "3",
        .container_id = "c-id",
        .role_instance_id = "r-id",
        .state = .not_ready,
        .sub_status = "Provisioning",
        .description = "waiting for <cloud-init> & friends",
    });
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "<State>NotReady</State>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<SubStatus>Provisioning</SubStatus>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "waiting for &lt;cloud-init&gt; &amp; friends") != null);
}

const agent_headers = [_]std.http.Header{
    .{ .name = "x-ms-agent-name", .value = agent_name },
    .{ .name = "x-ms-version", .value = protocol_version },
};

const xml_content_headers = [_]std.http.Header{
    .{ .name = "x-ms-agent-name", .value = agent_name },
    .{ .name = "x-ms-version", .value = protocol_version },
    .{ .name = "Content-Type", .value = "text/xml;charset=utf-8" },
};

/// Talks to the WireServer over plain HTTP (no TLS -- these endpoints are
/// only reachable from inside the guest VM, over a host-only,
/// non-routable-from-outside address).
pub const Client = struct {
    http_client: std.http.Client,
    /// Overridable for tests; defaults to the real WireServer address.
    endpoint: []const u8 = default_endpoint,

    pub const FetchError = std.http.Client.FetchError || error{UnexpectedStatus};

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Client {
        return .{ .http_client = .{ .allocator = allocator, .io = io } };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
    }

    /// Issues `GET /?comp=versions`. Returns the raw XML response body
    /// (caller-owned); parse it with `VersionInfo.parse`.
    pub fn fetchVersions(self: *Client, allocator: std.mem.Allocator) FetchError![]u8 {
        return self.getXml(allocator, "/?comp=versions");
    }

    /// Issues `GET /machine/?comp=goalstate`. Returns the raw XML response
    /// body (caller-owned); parse it with `GoalState.parse`.
    pub fn fetchGoalState(self: *Client, allocator: std.mem.Allocator) FetchError![]u8 {
        return self.getXml(allocator, "/machine/?comp=goalstate");
    }

    fn getXml(self: *Client, allocator: std.mem.Allocator, path: []const u8) FetchError![]u8 {
        const url = try std.fmt.allocPrint(allocator, "http://{s}{s}", .{ self.endpoint, path });
        defer allocator.free(url);

        var body: std.Io.Writer.Allocating = .init(allocator);
        errdefer body.deinit();

        const result = try self.http_client.fetch(.{
            .location = .{ .url = url },
            .response_writer = &body.writer,
            .extra_headers = &agent_headers,
        });
        if (result.status != .ok) return error.UnexpectedStatus;
        return body.toOwnedSlice();
    }

    /// Issues `POST /machine?comp=health` with `report`'s XML body,
    /// matching upstream's `report_health` -- marks the instance "Ready" (or
    /// reports a NotReady sub-status/description) to the WireServer.
    pub fn reportHealth(self: *Client, allocator: std.mem.Allocator, report: HealthReport) FetchError!void {
        const body = try buildHealthReportXml(allocator, report);
        defer allocator.free(body);

        const url = try std.fmt.allocPrint(allocator, "http://{s}/machine?comp=health", .{self.endpoint});
        defer allocator.free(url);

        const result = try self.http_client.fetch(.{
            .location = .{ .url = url },
            .payload = body,
            .extra_headers = &xml_content_headers,
        });
        if (result.status != .ok and result.status != .accepted) return error.UnexpectedStatus;
    }
};

const test_versions_xml =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<Versions>
    \\  <Preferred><Version>2012-11-30</Version></Preferred>
    \\  <Supported><Version>2010-12-15</Version><Version>2012-11-30</Version></Supported>
    \\</Versions>
;

const test_goalstate_xml =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
    \\   <Version>2012-11-30</Version>
    \\   <Incarnation>7</Incarnation>
    \\   <Container>
    \\     <ContainerId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</ContainerId>
    \\     <RoleInstanceList>
    \\       <RoleInstance>
    \\         <InstanceId>ffffffff-0000-1111-2222-333333333333.MachineRole_IN_0</InstanceId>
    \\         <State>Started</State>
    \\       </RoleInstance>
    \\     </RoleInstanceList>
    \\   </Container>
    \\ </GoalState>
;

/// Shared between the test's main thread and the stand-in server thread it
/// spawns; safe to read from the main thread only after `Thread.join()`
/// returns, which provides the necessary happens-before edge.
const ServerResult = struct {
    err: ?anyerror = null,
    health_report_body: ?[]u8 = null,
};

fn runStandInWireServer(allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server, result: *ServerResult) void {
    runStandInWireServerFallible(allocator, io, listener, result) catch |err| {
        result.err = err;
    };
}

fn runStandInWireServerFallible(allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server, result: *ServerResult) !void {
    var stream = try listener.accept(io);
    defer stream.close(io);

    var in_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &in_buf);
    var stream_writer = stream.writer(io, &out_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);

    var handled: usize = 0;
    while (handled < 3) : (handled += 1) {
        var request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing, error.ReadFailed => break,
            else => return err,
        };

        if (std.mem.indexOf(u8, request.head.target, "comp=versions") != null) {
            try request.respond(test_versions_xml, .{});
        } else if (std.mem.indexOf(u8, request.head.target, "comp=goalstate") != null) {
            try request.respond(test_goalstate_xml, .{});
        } else if (std.mem.indexOf(u8, request.head.target, "comp=health") != null) {
            var body_buf: [512]u8 = undefined;
            const body_reader = request.readerExpectNone(&body_buf);
            result.health_report_body = try body_reader.allocRemaining(allocator, .limited(8192));
            try request.respond("", .{});
        } else {
            try request.respond("", .{ .status = .not_found });
        }
    }
}

test "Client round-trips versions, goal state, and health report against a local WireServer stand-in" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 28163 } };
    var listener = try listen_address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var server_result: ServerResult = .{};
    const thread = try std.Thread.spawn(.{}, runStandInWireServer, .{ allocator, io, &listener, &server_result });

    var client: Client = .init(allocator, io);
    client.endpoint = "127.0.0.1:28163";
    defer client.deinit();

    const versions_body = try client.fetchVersions(allocator);
    defer allocator.free(versions_body);
    const info = try VersionInfo.parse(versions_body);
    try std.testing.expectEqualStrings(protocol_version, info.preferred().?);
    try std.testing.expect(info.isSupported(protocol_version));

    const goalstate_body = try client.fetchGoalState(allocator);
    defer allocator.free(goalstate_body);
    const gs = try GoalState.parse(goalstate_body);
    try std.testing.expectEqualStrings("7", gs.incarnation);

    try client.reportHealth(allocator, .{
        .incarnation = gs.incarnation,
        .container_id = gs.container_id,
        .role_instance_id = gs.role_instance_id,
        .state = .ready,
    });

    thread.join();

    try std.testing.expectEqual(@as(?anyerror, null), server_result.err);
    const health_body = server_result.health_report_body orelse return error.MissingHealthReportBody;
    defer allocator.free(health_body);
    try std.testing.expect(std.mem.indexOf(u8, health_body, "<GoalStateIncarnation>7</GoalStateIncarnation>") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_body, gs.container_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, health_body, gs.role_instance_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, health_body, "<State>Ready</State>") != null);
}

test {
    _ = xml;
}
