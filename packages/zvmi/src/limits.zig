//! The import limits every tree-building path enforces, the CLI flag that
//! raises each one, and the diagnostic that says which one was hit.
//!
//! The defaults are deliberately conservative: they are guardrails against a
//! malicious or corrupt source, not a statement about how large a real root
//! filesystem is. A full installed server with a desktop environment, a
//! toolchain, and vendor driver stacks routinely exceeds them, so every limit
//! is raisable from the command line rather than only from Zig.
//!
//! Enforcement sites report through `Diagnostic` instead of printing, because
//! they run deep inside the library where the caller's output stream, its
//! diagnostic format, and even whether a failure is fatal are all unknown.
//! The recorded breach carries the observed value, the configured limit, and
//! the flag that raises it, which is everything an operator needs to retry.

const std = @import("std");
const parseSize = @import("size.zig").parseSize;

/// Every limit a source import enforces. One enum value, one flag, one peak.
pub const Limit = enum {
    nodes,
    path_bytes,
    component_bytes,
    file_bytes,
    total_bytes,
    spool_bytes,
    xattrs_per_node,
    xattr_bytes_per_node,
    scan_metadata_bytes,
    source_file_bytes,

    /// The command-line flag that raises this limit. Spelled once, here, so
    /// the flag a failure names is the flag the parsers accept.
    pub fn flag(self: Limit) []const u8 {
        return switch (self) {
            .nodes => "--max-nodes",
            .path_bytes => "--max-path-bytes",
            .component_bytes => "--max-component-bytes",
            .file_bytes => "--max-file-bytes",
            .total_bytes => "--max-total-bytes",
            .spool_bytes => "--max-spool-bytes",
            .xattrs_per_node => "--max-xattrs-per-node",
            .xattr_bytes_per_node => "--max-xattr-bytes-per-node",
            .scan_metadata_bytes => "--max-scan-metadata-bytes",
            .source_file_bytes => "--max-source-file-bytes",
        };
    }

    /// What the measured number counts, for the human-readable message.
    pub fn unit(self: Limit) []const u8 {
        return switch (self) {
            .nodes => "nodes",
            .path_bytes => "bytes in one path",
            .component_bytes => "bytes in one path component",
            .file_bytes => "bytes in one file",
            .total_bytes => "total content bytes",
            .spool_bytes => "spooled bytes",
            .xattrs_per_node => "xattrs on one node",
            .xattr_bytes_per_node => "xattr bytes on one node",
            .scan_metadata_bytes => "scan metadata bytes",
            .source_file_bytes => "bytes in one replacement source file",
        };
    }

    /// The error a breach of this limit returns. Distinct per limit so a
    /// caller that never looks at the diagnostic can still tell them apart.
    pub fn err(self: Limit) Error {
        return switch (self) {
            .nodes => error.NodeLimitExceeded,
            .path_bytes => error.PathLimitExceeded,
            .component_bytes => error.ComponentLimitExceeded,
            .file_bytes => error.FileLimitExceeded,
            .total_bytes => error.TotalContentLimitExceeded,
            .spool_bytes => error.SpoolLimitExceeded,
            .xattrs_per_node => error.XattrLimitExceeded,
            .xattr_bytes_per_node => error.XattrByteLimitExceeded,
            .scan_metadata_bytes => error.ScanMetadataLimitExceeded,
            .source_file_bytes => error.SourceFileTooLarge,
        };
    }
};

pub const Error = error{
    NodeLimitExceeded,
    PathLimitExceeded,
    ComponentLimitExceeded,
    FileLimitExceeded,
    TotalContentLimitExceeded,
    SpoolLimitExceeded,
    XattrLimitExceeded,
    XattrByteLimitExceeded,
    ScanMetadataLimitExceeded,
    SourceFileTooLarge,
};

/// The limits an owned in-memory/spooled tree enforces while nodes are added.
/// Re-exported as `root_tree.Limits`.
pub const Limits = struct {
    max_nodes: usize = 1_000_000,
    max_path_bytes: usize = 4096,
    max_component_bytes: usize = 255,
    max_file_bytes: u64 = 16 * 1024 * 1024 * 1024,
    max_total_bytes: u64 = 64 * 1024 * 1024 * 1024,
    max_spool_bytes: u64 = 128 * 1024 * 1024 * 1024,
    max_xattrs_per_node: usize = 256,
    max_xattr_bytes_per_node: usize = 1024 * 1024,
};

const tree_defaults = Limits{};

/// Every limit a full source import enforces: the tree limits plus the two
/// the strict ext4 scanner and the replacement-file loader own. Flat rather
/// than nested so the plan document, the flags, and the reported peaks all
/// name each limit exactly once.
pub const ImportLimits = struct {
    max_nodes: usize = tree_defaults.max_nodes,
    max_path_bytes: usize = tree_defaults.max_path_bytes,
    max_component_bytes: usize = tree_defaults.max_component_bytes,
    max_file_bytes: u64 = tree_defaults.max_file_bytes,
    max_total_bytes: u64 = tree_defaults.max_total_bytes,
    max_spool_bytes: u64 = tree_defaults.max_spool_bytes,
    max_xattrs_per_node: usize = tree_defaults.max_xattrs_per_node,
    max_xattr_bytes_per_node: usize = tree_defaults.max_xattr_bytes_per_node,
    max_scan_metadata_bytes: usize = 256 * 1024 * 1024,
    max_source_file_bytes: u64 = 1024 * 1024 * 1024,

    pub fn tree(self: ImportLimits) Limits {
        return .{
            .max_nodes = self.max_nodes,
            .max_path_bytes = self.max_path_bytes,
            .max_component_bytes = self.max_component_bytes,
            .max_file_bytes = self.max_file_bytes,
            .max_total_bytes = self.max_total_bytes,
            .max_spool_bytes = self.max_spool_bytes,
            .max_xattrs_per_node = self.max_xattrs_per_node,
            .max_xattr_bytes_per_node = self.max_xattr_bytes_per_node,
        };
    }

    pub fn value(self: ImportLimits, limit: Limit) u64 {
        return switch (limit) {
            .nodes => self.max_nodes,
            .path_bytes => self.max_path_bytes,
            .component_bytes => self.max_component_bytes,
            .file_bytes => self.max_file_bytes,
            .total_bytes => self.max_total_bytes,
            .spool_bytes => self.max_spool_bytes,
            .xattrs_per_node => self.max_xattrs_per_node,
            .xattr_bytes_per_node => self.max_xattr_bytes_per_node,
            .scan_metadata_bytes => self.max_scan_metadata_bytes,
            .source_file_bytes => self.max_source_file_bytes,
        };
    }

    pub const SetError = error{
        /// Zero would reject every source, including an empty one.
        ZeroLimit,
        /// A count or byte total this host cannot even address.
        LimitOutOfRange,
    };

    pub fn set(self: *ImportLimits, limit: Limit, raised: u64) SetError!void {
        if (raised == 0) return error.ZeroLimit;
        switch (limit) {
            .nodes => self.max_nodes = try toUsize(raised),
            .path_bytes => self.max_path_bytes = try toUsize(raised),
            .component_bytes => self.max_component_bytes = try toUsize(raised),
            .file_bytes => self.max_file_bytes = raised,
            .total_bytes => self.max_total_bytes = raised,
            .spool_bytes => self.max_spool_bytes = raised,
            .xattrs_per_node => self.max_xattrs_per_node = try toUsize(raised),
            .xattr_bytes_per_node => self.max_xattr_bytes_per_node = try toUsize(raised),
            .scan_metadata_bytes => self.max_scan_metadata_bytes = try toUsize(raised),
            .source_file_bytes => self.max_source_file_bytes = raised,
        }
    }

    pub const ParseError = SetError || error{InvalidLimitValue};

    /// Applies `--max-...  <value>` if `flag` names a limit. Returns false
    /// when it names something else, so a command's own argument loop keeps
    /// rejecting genuinely unknown flags.
    pub fn parseFlag(self: *ImportLimits, flag: []const u8, text: []const u8) ParseError!bool {
        const limit = limitForFlag(flag) orelse return false;
        const raised = parseSize(text) catch return error.InvalidLimitValue;
        try self.set(limit, raised);
        return true;
    }
};

pub fn limitForFlag(flag: []const u8) ?Limit {
    inline for (comptime std.enums.values(Limit)) |limit| {
        if (std.mem.eql(u8, flag, comptime limit.flag())) return limit;
    }
    return null;
}

fn toUsize(value: u64) ImportLimits.SetError!usize {
    return std.math.cast(usize, value) orelse error.LimitOutOfRange;
}

/// The largest value each limit was measured at during an import. Reported
/// so a dry run can size a real run: every field is directly comparable to
/// the like-named `ImportLimits` field.
pub const Peaks = struct {
    nodes: u64 = 0,
    path_bytes: u64 = 0,
    component_bytes: u64 = 0,
    file_bytes: u64 = 0,
    total_bytes: u64 = 0,
    spool_bytes: u64 = 0,
    xattrs_per_node: u64 = 0,
    xattr_bytes_per_node: u64 = 0,
    scan_metadata_bytes: u64 = 0,
    source_file_bytes: u64 = 0,

    pub fn value(self: Peaks, limit: Limit) u64 {
        return switch (limit) {
            .nodes => self.nodes,
            .path_bytes => self.path_bytes,
            .component_bytes => self.component_bytes,
            .file_bytes => self.file_bytes,
            .total_bytes => self.total_bytes,
            .spool_bytes => self.spool_bytes,
            .xattrs_per_node => self.xattrs_per_node,
            .xattr_bytes_per_node => self.xattr_bytes_per_node,
            .scan_metadata_bytes => self.scan_metadata_bytes,
            .source_file_bytes => self.source_file_bytes,
        };
    }

    fn slot(self: *Peaks, limit: Limit) *u64 {
        return switch (limit) {
            .nodes => &self.nodes,
            .path_bytes => &self.path_bytes,
            .component_bytes => &self.component_bytes,
            .file_bytes => &self.file_bytes,
            .total_bytes => &self.total_bytes,
            .spool_bytes => &self.spool_bytes,
            .xattrs_per_node => &self.xattrs_per_node,
            .xattr_bytes_per_node => &self.xattr_bytes_per_node,
            .scan_metadata_bytes => &self.scan_metadata_bytes,
            .source_file_bytes => &self.source_file_bytes,
        };
    }
};

/// A limit that was passed, with everything needed to retry successfully.
pub const Exceeded = struct {
    limit: Limit,
    observed: u64,
    configured: u64,

    /// Upper bound on `describe`, so callers can size a stack buffer.
    pub const max_message_bytes = 192;

    pub fn describe(self: Exceeded, buffer: []u8) std.fmt.BufPrintError![]const u8 {
        return std.fmt.bufPrint(
            buffer,
            "{s}: {d} {s} exceeds the configured limit of {d}; raise it with {s} <value>",
            .{
                @errorName(self.limit.err()),
                self.observed,
                self.limit.unit(),
                self.configured,
                self.limit.flag(),
            },
        );
    }

    /// Upper bound on `remediation`.
    pub const max_remediation_bytes = 128;

    /// The remediation half of the diagnostic: the exact flag, and a value
    /// that is known to clear this particular breach.
    pub fn remediation(self: Exceeded, buffer: []u8) std.fmt.BufPrintError![]const u8 {
        return std.fmt.bufPrint(
            buffer,
            "raise the limit with {s} {d} or higher",
            .{ self.limit.flag(), self.observed },
        );
    }
};

/// Where enforcement sites report. Optional at every call site: a caller that
/// only wants the error passes null and pays nothing.
pub const Diagnostic = struct {
    peaks: Peaks = .{},
    /// The first breach, which is also the one that stopped the import. Later
    /// breaches cannot happen, but a reused diagnostic must not lose the
    /// original cause to a subsequent probe.
    exceeded: ?Exceeded = null,

    pub fn observe(self: *Diagnostic, limit: Limit, measured: u64) void {
        const peak = self.peaks.slot(limit);
        if (measured > peak.*) peak.* = measured;
    }

    pub fn record(self: *Diagnostic, limit: Limit, measured: u64, configured: u64) void {
        self.observe(limit, measured);
        if (self.exceeded == null) {
            self.exceeded = .{
                .limit = limit,
                .observed = measured,
                .configured = configured,
            };
        }
    }
};

/// Records a peak when a diagnostic is attached.
pub fn observe(diagnostic: ?*Diagnostic, limit: Limit, measured: u64) void {
    if (diagnostic) |sink| sink.observe(limit, measured);
}

/// Records a breach and returns the error naming it. Enforcement sites read
/// `return limits.exceeded(...)` so the record and the error cannot diverge.
pub fn exceeded(
    diagnostic: ?*Diagnostic,
    limit: Limit,
    measured: u64,
    configured: u64,
) Error {
    if (diagnostic) |sink| sink.record(limit, measured, configured);
    return limit.err();
}

test "every limit has a distinct flag, unit, and error" {
    const values = comptime std.enums.values(Limit);
    inline for (values, 0..) |limit, index| {
        try std.testing.expect(std.mem.startsWith(u8, limit.flag(), "--max-"));
        try std.testing.expect(limit.unit().len != 0);
        inline for (values[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, limit.flag(), other.flag()));
            try std.testing.expect(limit.err() != other.err());
        }
    }
}

test "limitForFlag round-trips every flag" {
    inline for (comptime std.enums.values(Limit)) |limit| {
        try std.testing.expectEqual(limit, limitForFlag(limit.flag()).?);
    }
    try std.testing.expectEqual(@as(?Limit, null), limitForFlag("--max-oci-blob-size"));
    try std.testing.expectEqual(@as(?Limit, null), limitForFlag("--size"));
}

test "parseFlag raises exactly the named limit" {
    var configured = ImportLimits{};
    try std.testing.expect(try configured.parseFlag("--max-nodes", "8000000"));
    try std.testing.expectEqual(@as(usize, 8_000_000), configured.max_nodes);
    try std.testing.expect(try configured.parseFlag("--max-file-bytes", "32G"));
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024 * 1024), configured.max_file_bytes);
    try std.testing.expectEqual(
        @as(u64, tree_defaults.max_total_bytes),
        configured.max_total_bytes,
    );
    try std.testing.expect(!try configured.parseFlag("--size", "20G"));
}

test "parseFlag rejects values that cannot be a limit" {
    var configured = ImportLimits{};
    try std.testing.expectError(error.ZeroLimit, configured.parseFlag("--max-nodes", "0"));
    try std.testing.expectError(
        error.InvalidLimitValue,
        configured.parseFlag("--max-nodes", "lots"),
    );
    try std.testing.expectError(
        error.InvalidLimitValue,
        configured.parseFlag("--max-spool-bytes", "1P"),
    );
}

test "ImportLimits.tree carries the tree limits unchanged" {
    var configured = ImportLimits{};
    try std.testing.expect(try configured.parseFlag("--max-spool-bytes", "512G"));
    try std.testing.expectEqual(
        @as(u64, 512 * 1024 * 1024 * 1024),
        configured.tree().max_spool_bytes,
    );
    try std.testing.expectEqual(tree_defaults.max_nodes, configured.tree().max_nodes);
}

test "ImportLimits.value reports every configured limit" {
    var configured = ImportLimits{};
    inline for (comptime std.enums.values(Limit)) |limit| {
        try configured.set(limit, 4096);
        try std.testing.expectEqual(@as(u64, 4096), configured.value(limit));
    }
}

test "the recorded breach names the observed value, the limit, and the flag" {
    var diagnostic = Diagnostic{};
    const err = exceeded(&diagnostic, .nodes, 1_000_001, 1_000_000);

    try std.testing.expectEqual(error.NodeLimitExceeded, err);
    try std.testing.expectEqual(Limit.nodes, diagnostic.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 1_000_001), diagnostic.exceeded.?.observed);
    try std.testing.expectEqual(@as(u64, 1_000_000), diagnostic.exceeded.?.configured);

    var buffer: [Exceeded.max_message_bytes]u8 = undefined;
    const message = try diagnostic.exceeded.?.describe(&buffer);
    try std.testing.expect(std.mem.indexOf(u8, message, "NodeLimitExceeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "1000001 nodes") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "1000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--max-nodes") != null);
}

test "every limit's message fits the advertised buffer" {
    inline for (comptime std.enums.values(Limit)) |limit| {
        var buffer: [Exceeded.max_message_bytes]u8 = undefined;
        const breach = Exceeded{
            .limit = limit,
            .observed = std.math.maxInt(u64),
            .configured = std.math.maxInt(u64),
        };
        _ = try breach.describe(&buffer);
    }
}

test "a breach keeps the first cause and still tracks later peaks" {
    var diagnostic = Diagnostic{};
    exceeded(&diagnostic, .file_bytes, 20, 10) catch {};
    exceeded(&diagnostic, .nodes, 5, 4) catch {};

    try std.testing.expectEqual(Limit.file_bytes, diagnostic.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 20), diagnostic.peaks.file_bytes);
    try std.testing.expectEqual(@as(u64, 5), diagnostic.peaks.nodes);
}

test "peaks keep the largest measurement per limit" {
    var diagnostic = Diagnostic{};
    diagnostic.observe(.spool_bytes, 100);
    diagnostic.observe(.spool_bytes, 40);
    diagnostic.observe(.spool_bytes, 900);
    diagnostic.observe(.path_bytes, 12);

    try std.testing.expectEqual(@as(u64, 900), diagnostic.peaks.spool_bytes);
    try std.testing.expectEqual(@as(u64, 12), diagnostic.peaks.value(.path_bytes));
    try std.testing.expectEqual(@as(u64, 0), diagnostic.peaks.value(.nodes));
    try std.testing.expectEqual(@as(?Exceeded, null), diagnostic.exceeded);
}

test "an absent diagnostic still returns the naming error" {
    try std.testing.expectEqual(
        error.SpoolLimitExceeded,
        exceeded(null, .spool_bytes, 3, 2),
    );
    observe(null, .spool_bytes, 3);
}
