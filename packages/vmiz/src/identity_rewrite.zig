//! Reconciling an imported system's configuration with the identifiers the
//! rebuilt image actually has.
//!
//! Rebuilding an installed system into a different layout retires
//! identifiers. A `/boot` filesystem folded into the root stops existing, so
//! every `UUID=`/`PARTUUID=` that named it now names nothing; the same is
//! true of an ESP merged in at `/boot/efi`. The imported guest still carries
//! those identifiers in `/etc/fstab` and in its bootloader configuration, and
//! an image that boots is one where both have been corrected. The
//! alternative -- mounting the result and running `grub-install` /
//! `update-grub` in a chroot -- is precisely the privileged, host-dependent
//! step this project exists to avoid.
//!
//! Three deliberate choices shape everything here:
//!
//! * **Rewriting is surgical, never regenerative.** `/etc/fstab` is spliced
//!   in place, not re-emitted from a parsed model: a real system's fstab
//!   carries bind mounts, network shares, `tmpfs` entries and comments that
//!   explain them, and a "minimal correct fstab" would silently throw all of
//!   that away. The same argument applies with more force to a distro
//!   `grub.cfg`, whose menu structure no re-implementation of
//!   `grub-mkconfig` would reproduce faithfully.
//! * **A merged-away filesystem's entry is dropped, not rewritten.** Its
//!   content is a plain directory inside another filesystem now, and
//!   mounting anything over that directory would hide the very content the
//!   merge just imported.
//! * **The verification pass is the safety net and it fails the build.** A
//!   stale identifier that survives produces an image that drops to an
//!   initramfs prompt with an unhelpful message, which is the worst failure
//!   mode available. Everything the rewriter cannot fix -- an identifier
//!   embedded in GRUB's `core.img`, a `grubenv`, a signed EFI binary -- is
//!   therefore reported by name rather than hoped over, and the documented
//!   answer is the `unsafe_chroot` escape hatch.

const std = @import("std");
const root_tree = @import("root_tree.zig");

const Allocator = std.mem.Allocator;

/// Longest identifier this module will carry. A canonical UUID is 36 bytes,
/// a GPT partition name up to 36 characters, an ext4 label 16 and a FAT
/// volume label 11; the cap exists so a diagnostic can hold a copy without
/// allocating on a failure path.
pub const max_identifier_bytes: usize = 64;

/// The length of a canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` UUID.
/// Identifiers this long are specific enough that an occurrence anywhere in
/// a file is a reference; shorter ones are not (see `matchesAt`).
pub const canonical_uuid_bytes: usize = 36;

/// Upper bound on a configuration file the rewriter will read into memory.
/// A bootloader configuration is text a human maintains; anything past this
/// is not one, and refusing beats silently rewriting an unbounded read.
pub const max_config_bytes: u64 = 8 * 1024 * 1024;

pub const Error = error{
    /// An identifier in the plan is longer than `max_identifier_bytes`, or
    /// empty. Both would make matching meaningless rather than merely wrong.
    InvalidIdentifier,
    /// A mount point or ESP root in the plan is not an absolute, normalized
    /// path. Normalizing it here would let two spellings of one path be
    /// treated as two different places.
    InvalidRewritePath,
    /// A file in the rewrite scope is larger than `max_config_bytes`.
    ConfigFileTooLarge,
    /// The output still names an identifier the rebuild retired. The
    /// offending file is in the `Diagnostic` the caller supplied.
    StaleFilesystemIdentifier,
};

/// The four ways fstab, GRUB and the kernel command line name a filesystem
/// or a partition.
pub const Kind = enum {
    filesystem_uuid,
    partition_uuid,
    filesystem_label,
    partition_label,

    /// The `KEY=` prefix the identifier is spelled with. Written once, here,
    /// so the tag the parser accepts is the tag the rewriter emits.
    pub fn tag(self: Kind) []const u8 {
        return switch (self) {
            .filesystem_uuid => "UUID",
            .partition_uuid => "PARTUUID",
            .filesystem_label => "LABEL",
            .partition_label => "PARTLABEL",
        };
    }

    /// Whether the value is hexadecimal. UUIDs compare case-insensitively --
    /// `blkid` prints lowercase, plenty of installers write uppercase, and
    /// they name the same filesystem -- while a label is an arbitrary byte
    /// string whose case is part of it.
    pub fn isUuid(self: Kind) bool {
        return switch (self) {
            .filesystem_uuid, .partition_uuid => true,
            .filesystem_label, .partition_label => false,
        };
    }
};

/// Every way one filesystem can be named. A null field means "not known",
/// which is not the same as "empty": an MBR disk with no signature has no
/// PARTUUID at all, and claiming one would invent an identifier.
pub const Identifiers = struct {
    filesystem_uuid: ?[]const u8 = null,
    partition_uuid: ?[]const u8 = null,
    filesystem_label: ?[]const u8 = null,
    partition_label: ?[]const u8 = null,

    pub fn get(self: Identifiers, kind: Kind) ?[]const u8 {
        return switch (kind) {
            .filesystem_uuid => self.filesystem_uuid,
            .partition_uuid => self.partition_uuid,
            .filesystem_label => self.filesystem_label,
            .partition_label => self.partition_label,
        };
    }
};

/// The two filesystem kinds this project can write a root as, spelled the way
/// `/etc/fstab`'s third field and a kernel `rootfstype=` name them. Everything
/// else an imported system might use (btrfs, f2fs, an unrecognized word) is
/// deliberately absent: the only stale-type confusion a rebuild introduces is
/// converting between these two, and a value the writer does not produce is one
/// this module must never invent by rewriting toward it.
pub const FilesystemType = enum {
    ext4,
    xfs,

    pub fn name(self: FilesystemType) []const u8 {
        return switch (self) {
            .ext4 => "ext4",
            .xfs => "xfs",
        };
    }

    /// Parses exactly the two kinds this module understands, case-sensitively
    /// (fstab and the kernel both spell them lowercase). Any other word -- a
    /// filesystem this project does not write, a `swap`, an `auto` -- returns
    /// null so the caller leaves it untouched rather than guessing.
    pub fn parse(text: []const u8) ?FilesystemType {
        if (std.mem.eql(u8, text, "ext4")) return .ext4;
        if (std.mem.eql(u8, text, "xfs")) return .xfs;
        return null;
    }
};

/// What became of one source filesystem.
pub const Filesystem = struct {
    /// How the imported configuration still names it.
    before: Identifiers,
    /// What names the same content in the rebuilt image. For a filesystem
    /// that survived as a filesystem this is its own new identifiers; for a
    /// merged one it is the identifiers of the filesystem that absorbed it,
    /// because that is what a reference to the old content has to name now.
    /// A field left null retires without a replacement: references to it are
    /// stale and there is nothing to put in their place, which is exactly
    /// what the verification pass exists to report.
    after: Identifiers = .{},
    /// Set when this filesystem stopped being a mount of its own: its
    /// content is now a plain directory at this absolute path inside the
    /// filesystem `after` names. An `/etc/fstab` entry for it is removed
    /// rather than rewritten.
    merged_at: ?[]const u8 = null,
    /// The kind the rebuilt filesystem actually is, set only on the entry that
    /// remains the root (`merged_at` null and the successor root). Null on
    /// every other entry, and null whenever a caller does not thread a kind
    /// through at all -- which is what keeps this backward-compatible: a plan
    /// built the old way rewrites identifiers exactly as before and touches no
    /// filesystem-type field. When it is set and the imported `/etc/fstab` or
    /// kernel command line names a *different* ext4/xfs type for the root, that
    /// stale type is corrected to this one.
    root_filesystem_type: ?FilesystemType = null,
};

/// The whole reconciliation: what happened to each source filesystem, plus
/// where any EFI system partition ended up in the tree.
pub const Plan = struct {
    filesystems: []const Filesystem = &.{},
    /// Absolute paths of merged EFI system partitions. Named separately
    /// because the ESP is scanned in full by the verification pass -- a
    /// vendor `grub.cfg`, BLS entries and shim's own configuration all live
    /// there -- while a merged `/boot` is not, since its kernels and
    /// initramfs images are megabytes of compressed payload in which no
    /// identifier is either readable or rewritable.
    esp_roots: []const []const u8 = &.{},
    /// Set when the tree being reconciled *is* an EFI system partition
    /// rather than a root filesystem that absorbed one. `esp_roots` cannot
    /// express that: it names a subtree, and an ESP written as its own
    /// partition has no path prefix to name. Without this, an assembled
    /// image's ESP keeps a `grub.cfg` naming the root filesystem UUID the
    /// source had, and nothing catches it until the image fails to boot.
    tree_is_esp: bool = false,

    pub fn validate(self: Plan) Error!void {
        for (self.filesystems) |filesystem| {
            inline for (comptime std.enums.values(Kind)) |kind| {
                if (filesystem.before.get(kind)) |value| try validateIdentifier(value);
                if (filesystem.after.get(kind)) |value| try validateIdentifier(value);
            }
            if (filesystem.merged_at) |path| try validateAbsolutePath(path);
        }
        for (self.esp_roots) |path| try validateAbsolutePath(path);
    }

    /// Whether anything at all changed. A rebuild that preserved every
    /// identifier and merged nothing has no work to do, and saying so lets
    /// the common case skip reading a single file.
    pub fn retiresAnything(self: Plan) bool {
        for (self.filesystems) |filesystem| {
            inline for (comptime std.enums.values(Kind)) |kind| {
                if (isRetired(filesystem, kind)) return true;
            }
        }
        return false;
    }

    /// The kind the rebuilt root filesystem actually is, or null when no entry
    /// carries one -- an older caller that never threaded a kind, or a plan
    /// that simply did not record it. Only the surviving root entry is ever
    /// tagged (a merged filesystem is a directory now, not a root), so the
    /// first non-merged entry that carries a kind is the answer.
    pub fn rootType(self: Plan) ?FilesystemType {
        for (self.filesystems) |filesystem| {
            if (filesystem.merged_at != null) continue;
            if (filesystem.root_filesystem_type) |kind| return kind;
        }
        return null;
    }

    fn find(self: Plan, kind: Kind, value: []const u8) ?Filesystem {
        for (self.filesystems) |filesystem| {
            const before = filesystem.before.get(kind) orelse continue;
            if (identifierEql(kind, before, value)) return filesystem;
        }
        return null;
    }
};

/// Whether references to `kind` on this filesystem name something that no
/// longer exists. An identifier is retired when the rebuild gave it a
/// different value, or when the caller could not say what the new value is.
///
/// A merge is not special-cased here on purpose. A merged filesystem's
/// identifiers are retired because `after` names the filesystem that absorbed
/// it, which is a different filesystem; in the degenerate case where the two
/// carry the same identifier a reference still resolves to the right content,
/// and calling it stale would fail a build that is in fact correct. Dropping
/// an fstab entry, by contrast, depends on the merge and not on this.
fn isRetired(filesystem: Filesystem, kind: Kind) bool {
    const before = filesystem.before.get(kind) orelse return false;
    const after = filesystem.after.get(kind) orelse return true;
    return !identifierEql(kind, before, after);
}

fn validateIdentifier(value: []const u8) Error!void {
    if (value.len == 0 or value.len > max_identifier_bytes) return error.InvalidIdentifier;
}

fn validateAbsolutePath(path: []const u8) Error!void {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') {
        return error.InvalidRewritePath;
    }
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidRewritePath;
        }
    }
}

fn identifierEql(kind: Kind, a: []const u8, b: []const u8) bool {
    return if (kind.isUuid())
        std.ascii.eqlIgnoreCase(a, b)
    else
        std.mem.eql(u8, a, b);
}

/// Formats a 16-byte filesystem UUID in plain RFC 4122 byte order, which is
/// how ext4's superblock `s_uuid`, libblkid and every `UUID=` in an fstab
/// spell it.
///
/// Deliberately not `guid.formatLower`, which implements the mixed-endian
/// Microsoft `GUID` convention GPT uses for partition GUIDs. Using that here
/// would byte-swap the first three fields and produce a string that names no
/// filesystem at all -- and, worse, one that looks entirely plausible.
pub fn formatFilesystemUuid(buffer: *[canonical_uuid_bytes]u8, bytes: *const [16]u8) []const u8 {
    _ = std.fmt.bufPrint(
        buffer,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-" ++
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        },
    ) catch unreachable;
    return buffer;
}

/// Length of a FAT volume serial in the `XXXX-XXXX` form `blkid` reports and
/// an fstab names it by. It is not a UUID and there is no wider identifier a
/// FAT volume could be named by, which is why it is matched as a whole token
/// only; see `matchesAt`.
pub const fat_serial_bytes: usize = 9;

/// Formats a FAT volume serial the way `blkid` prints it: uppercase, with the
/// high and low halves separated.
pub fn formatFatVolumeSerial(buffer: *[fat_serial_bytes]u8, volume_id: u32) []const u8 {
    _ = std.fmt.bufPrint(buffer, "{X:0>4}-{X:0>4}", .{
        @as(u16, @truncate(volume_id >> 16)),
        @as(u16, @truncate(volume_id)),
    }) catch unreachable;
    return buffer;
}

/// Trims a fixed-width, padded on-disk label field down to the label itself.
/// ext4 pads with NULs and FAT with spaces, and neither padding byte is part
/// of the name any tool prints. An all-padding field is no label at all,
/// which is reported as null rather than as an empty identifier that would
/// match nothing.
pub fn trimLabel(field: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, field, " \x00");
    return if (trimmed.len == 0) null else trimmed;
}

/// How much the rewriter changed, and how much it could not.
pub const Report = struct {
    /// Identifiers the rebuild retired, summed over every filesystem. Zero
    /// means the rewrite and the verification pass were both no-ops.
    retired_identifiers: usize = 0,
    fstab_entries_rewritten: usize = 0,
    /// Root `/etc/fstab` entries whose third (filesystem-type) field was
    /// corrected from a stale ext4/xfs value to the kind the root now is.
    /// Counted separately from `fstab_entries_rewritten`, which stays a count
    /// of *identifier* splices, so a type-only correction is still visible.
    fstab_types_rewritten: usize = 0,
    fstab_entries_dropped: usize = 0,
    /// fstab entries naming a retired identifier for which the plan supplied
    /// no replacement. Left exactly as they were and reported, because a
    /// guess in an fstab is a boot failure with extra steps.
    fstab_entries_unresolved: usize = 0,
    config_files_rewritten: usize = 0,
    config_references_rewritten: usize = 0,
    /// The subset of `config_references_rewritten` that were `rootfstype=`
    /// filesystem-type corrections on a kernel command line rather than
    /// identifier replacements. Zero unless the root's kind changed.
    config_rootfstype_rewritten: usize = 0,
    /// Files the verification pass read in full.
    verified_files: usize = 0,
    /// Occurrences of a retired identifier that survived every rewrite.
    /// Non-zero always accompanies `error.StaleFilesystemIdentifier` under
    /// `.rewrite_and_verify`, and is reported without failing under
    /// `.rewrite_only`.
    stale_references: usize = 0,
};

/// One surviving reference to a retired identifier, carried by value so the
/// caller still has it after the tree it was found in is gone.
///
/// The path is copied into a fixed buffer rather than allocated: this is
/// reported on a failure path, where an allocator that fails would replace a
/// precise diagnostic with a bare `OutOfMemory`. A path longer than the
/// buffer is recorded truncated and says so.
pub const Stale = struct {
    pub const path_capacity: usize = 1024;

    kind: Kind,
    identifier_buffer: [max_identifier_bytes]u8 = undefined,
    identifier_length: usize = 0,
    path_buffer: [path_capacity]u8 = undefined,
    path_length: usize = 0,
    path_truncated: bool = false,
    /// Byte offset of the occurrence within the file, which is what makes a
    /// hit inside a large binary actionable.
    offset: u64 = 0,

    pub fn identifier(self: *const Stale) []const u8 {
        return self.identifier_buffer[0..self.identifier_length];
    }

    pub fn path(self: *const Stale) []const u8 {
        return self.path_buffer[0..self.path_length];
    }

    /// Upper bound on `describe`, so callers can size a stack buffer.
    pub const max_message_bytes: usize = path_capacity + max_identifier_bytes + 128;

    pub fn describe(self: *const Stale, buffer: []u8) std.fmt.BufPrintError![]const u8 {
        return std.fmt.bufPrint(
            buffer,
            "/{s} still names the retired {s} {s} at offset {d}{s}",
            .{
                self.path(),
                self.kind.tag(),
                self.identifier(),
                self.offset,
                if (self.path_truncated) " (path truncated)" else "",
            },
        );
    }

    /// Upper bound on `remediation`.
    pub const max_remediation_bytes: usize = path_capacity + 160;

    pub fn remediation(self: *const Stale, buffer: []u8) std.fmt.BufPrintError![]const u8 {
        return std.fmt.bufPrint(
            buffer,
            "correct /{s} in the source, or reinstall the bootloader with the unsafe_chroot backend",
            .{self.path()},
        );
    }
};

/// Where the rewriter reports what it could not fix. Optional at every call
/// site: a caller that only wants the error passes null and pays nothing.
pub const Diagnostic = struct {
    /// The first surviving reference, which is also the one that stops the
    /// build. Later ones are counted in `Report.stale_references`; keeping
    /// only the first avoids an unbounded diagnostic on a tree where one
    /// identifier appears in a hundred places.
    stale: ?Stale = null,

    pub fn record(
        self: *Diagnostic,
        kind: Kind,
        value: []const u8,
        path: []const u8,
        offset: u64,
    ) void {
        if (self.stale != null) return;
        var entry = Stale{ .kind = kind, .offset = offset };
        entry.identifier_length = @min(value.len, entry.identifier_buffer.len);
        @memcpy(entry.identifier_buffer[0..entry.identifier_length], value[0..entry.identifier_length]);
        entry.path_length = @min(path.len, entry.path_buffer.len);
        entry.path_truncated = path.len > entry.path_buffer.len;
        @memcpy(entry.path_buffer[0..entry.path_length], path[0..entry.path_length]);
        // Published only once fully filled: a half-written diagnostic read by
        // a caller on the failure path is worse than none.
        self.stale = entry;
    }
};

/// What `apply` is allowed to do.
pub const Policy = enum {
    /// Rewrite, then refuse to publish an image that still names a retired
    /// identifier. The default everywhere, because the failure it prevents
    /// is invisible until the image is booted.
    rewrite_and_verify,
    /// Rewrite and report what is still stale without failing, for an
    /// operator who intends to finish the job with `unsafe_chroot`.
    rewrite_only,
    /// Read the tree without editing it and refuse when a retired
    /// identifier survives. Used to verify an image that has already been
    /// written: rewriting first would repair the very reference the pass
    /// exists to catch.
    verify_only,
    /// Touch nothing. The caller owns the bootability of the result.
    off,
};

/// Rewrites an imported tree's `/etc/fstab` and bootloader configuration for
/// the identifiers the rebuilt image actually has, then -- under
/// `.rewrite_and_verify` -- refuses the build if any retired identifier
/// survived anywhere the pass looks.
pub fn apply(
    allocator: Allocator,
    tree: *root_tree.RootTree,
    plan: Plan,
    policy: Policy,
    diagnostic: ?*Diagnostic,
) !Report {
    if (policy == .off) return .{};
    try plan.validate();

    var report = Report{ .retired_identifiers = countRetired(plan) };
    if (report.retired_identifiers == 0 and plan.rootType() == null) return report;

    var scope = try Scope.init(allocator, plan);
    defer scope.deinit();

    if (policy != .verify_only) {
        try rewriteTreeFiles(allocator, tree, plan, scope, &report);
    }
    try verify(allocator, tree, plan, scope, &report, diagnostic);
    if (policy != .rewrite_only and report.stale_references != 0) {
        return error.StaleFilesystemIdentifier;
    }
    return report;
}

fn countRetired(plan: Plan) usize {
    var total: usize = 0;
    for (plan.filesystems) |filesystem| {
        inline for (comptime std.enums.values(Kind)) |kind| {
            if (isRetired(filesystem, kind)) total += 1;
        }
    }
    return total;
}

/// The tree-relative paths the two passes work on. `RootTree` stores paths
/// without a leading slash, while a plan states them the way an operator
/// writes them, so the conversion happens once here rather than at every
/// comparison.
const Scope = struct {
    allocator: Allocator,
    esp_roots: [][]const u8,
    whole_tree: bool,

    fn init(allocator: Allocator, plan: Plan) Allocator.Error!Scope {
        const roots = try allocator.alloc([]const u8, plan.esp_roots.len);
        for (plan.esp_roots, roots) |absolute, *slot| slot.* = absolute[1..];
        return .{ .allocator = allocator, .esp_roots = roots, .whole_tree = plan.tree_is_esp };
    }

    fn deinit(self: *Scope) void {
        self.allocator.free(self.esp_roots);
        self.* = undefined;
    }

    fn underEsp(self: Scope, path: []const u8) bool {
        if (self.whole_tree) return true;
        for (self.esp_roots) |root| {
            if (pathContains(root, path)) return true;
        }
        return false;
    }
};

fn pathContains(parent: []const u8, candidate: []const u8) bool {
    return candidate.len > parent.len and
        std.mem.startsWith(u8, candidate, parent) and
        candidate[parent.len] == '/';
}

fn hasSuffix(path: []const u8, suffix: []const u8) bool {
    return std.mem.endsWith(u8, path, suffix);
}

/// Files the rewriter edits: plain-text bootloader configuration, and
/// nothing else. Deliberately narrower than the set the verification pass
/// reads -- editing a `core.img` or a signed EFI binary in place would
/// produce a file that still fails to boot, only less obviously.
fn isConfigRewriteTarget(path: []const u8, scope: Scope) bool {
    if (std.mem.eql(u8, path, "etc/default/grub")) return true;
    if (std.mem.eql(u8, path, "etc/kernel/cmdline")) return true;
    if (pathContains("etc/default/grub.d", path)) return true;
    const in_boot_config = pathContains("boot/grub", path) or
        pathContains("boot/grub2", path) or
        pathContains("boot/loader", path) or
        scope.underEsp(path);
    return in_boot_config and (hasSuffix(path, ".cfg") or hasSuffix(path, ".conf"));
}

/// Files the verification pass reads. Everything under the bootloader's own
/// directories and the ESP, not only what the rewriter understands, because
/// the point of the pass is to catch what the rewriter missed.
fn isVerificationTarget(path: []const u8, scope: Scope) bool {
    if (std.mem.eql(u8, path, "etc/fstab")) return true;
    if (std.mem.eql(u8, path, "etc/crypttab")) return true;
    if (std.mem.eql(u8, path, "etc/default/grub")) return true;
    if (std.mem.eql(u8, path, "etc/kernel/cmdline")) return true;
    if (pathContains("etc/default/grub.d", path)) return true;
    if (pathContains("boot/grub", path)) return true;
    if (pathContains("boot/grub2", path)) return true;
    if (pathContains("boot/loader", path)) return true;
    return scope.underEsp(path);
}

/// Rewrites every file in scope. Paths are collected first because writing a
/// node back appends to the tree, and iterating a list while appending to it
/// would visit whatever landed where the cursor was.
fn rewriteTreeFiles(
    allocator: Allocator,
    tree: *root_tree.RootTree,
    plan: Plan,
    scope: Scope,
    report: *Report,
) !void {
    var targets = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (targets.items) |path| allocator.free(path);
        targets.deinit();
    }

    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const node = tree.nodeView(index);
        if (node.kind != .file) continue;
        const is_fstab = std.mem.eql(u8, node.path, "etc/fstab");
        if (!is_fstab and !isConfigRewriteTarget(node.path, scope)) continue;
        try targets.append(try allocator.dupe(u8, node.path));
    }

    for (targets.items) |path| {
        if (std.mem.eql(u8, path, "etc/fstab")) {
            try rewriteTreeFstab(allocator, tree, path, plan, report);
        } else {
            try rewriteTreeConfig(allocator, tree, path, plan, report);
        }
    }
}

fn rewriteTreeFstab(
    allocator: Allocator,
    tree: *root_tree.RootTree,
    path: []const u8,
    plan: Plan,
    report: *Report,
) !void {
    const original = try tree.readFileAlloc(allocator, path, max_config_bytes);
    defer allocator.free(original);

    var fstab = FstabReport{};
    const rewritten = try rewriteFstab(allocator, original, plan, &fstab);
    defer allocator.free(rewritten);
    report.fstab_entries_rewritten += fstab.entries_rewritten;
    report.fstab_types_rewritten += fstab.types_rewritten;
    report.fstab_entries_dropped += fstab.entries_dropped;
    report.fstab_entries_unresolved += fstab.entries_unresolved;
    if (std.mem.eql(u8, original, rewritten)) return;
    try replaceFileContent(tree, path, rewritten);
}

fn rewriteTreeConfig(
    allocator: Allocator,
    tree: *root_tree.RootTree,
    path: []const u8,
    plan: Plan,
    report: *Report,
) !void {
    const original = tree.readFileAlloc(allocator, path, max_config_bytes) catch |err| switch (err) {
        error.FileLimitExceeded => return error.ConfigFileTooLarge,
        else => return err,
    };
    defer allocator.free(original);

    var config = ConfigReport{};
    const rewritten = try rewriteConfig(allocator, original, plan, &config);
    defer allocator.free(rewritten);
    if (config.references == 0) return;
    report.config_files_rewritten += 1;
    report.config_references_rewritten += config.references;
    report.config_rootfstype_rewritten += config.rootfstype_rewritten;
    try replaceFileContent(tree, path, rewritten);
}

/// Replaces a file's bytes and nothing else. Ownership, permissions,
/// timestamps and extended attributes are read back off the node and written
/// through unchanged: a `grub.cfg` that loses its SELinux label because its
/// UUID was corrected would trade one boot failure for another.
fn replaceFileContent(tree: *root_tree.RootTree, path: []const u8, bytes: []const u8) !void {
    const node = tree.findNode(path) orelse return error.MissingNode;
    try tree.putFileBytes(path, bytes, node.metadata);
}

pub const FstabReport = struct {
    entries_rewritten: usize = 0,
    /// Root entries whose filesystem-type (third) field was corrected. Kept
    /// apart from `entries_rewritten` so a type-only fix -- an entry whose
    /// identifier did not change but whose ext4/xfs type did -- is still
    /// counted rather than lost.
    types_rewritten: usize = 0,
    entries_dropped: usize = 0,
    entries_unresolved: usize = 0,
};

/// Rewrites `/etc/fstab` for the new identifiers, returning owned bytes.
///
/// Every line that does not describe a filesystem the rebuild touched is
/// copied out byte for byte -- the same spacing, the same field padding, the
/// same comments, the same trailing whitespace, the same absence of a final
/// newline. A rewritten line keeps everything except the identifier's value,
/// which is spliced in place. This is why the function works on raw line
/// slices rather than on a parsed representation it would have to re-render.
pub fn rewriteFstab(
    allocator: Allocator,
    original: []const u8,
    plan: Plan,
    report: *FstabReport,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    try out.ensureTotalCapacity(original.len);

    var cursor: usize = 0;
    while (cursor < original.len) {
        const newline = std.mem.indexOfScalarPos(u8, original, cursor, '\n');
        const end = if (newline) |index| index + 1 else original.len;
        try rewriteFstabLine(allocator, &out, original[cursor..end], plan, report);
        cursor = end;
    }
    return out.toOwnedSlice();
}

const Field = struct {
    start: usize,
    text: []const u8,
};

/// Splits an fstab line the way the kernel's own parser does: on runs of
/// spaces and tabs, with no quoting. Offsets are kept so a rewrite can
/// address the original bytes instead of re-rendering them.
const FieldIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn next(self: *FieldIterator) ?Field {
        while (self.cursor < self.bytes.len and isBlank(self.bytes[self.cursor])) {
            self.cursor += 1;
        }
        if (self.cursor >= self.bytes.len) return null;
        const start = self.cursor;
        while (self.cursor < self.bytes.len and !isBlank(self.bytes[self.cursor])) {
            self.cursor += 1;
        }
        return .{ .start = start, .text = self.bytes[start..self.cursor] };
    }

    fn isBlank(byte: u8) bool {
        return byte == ' ' or byte == '\t';
    }
};

fn rewriteFstabLine(
    allocator: Allocator,
    out: *std.array_list.Managed(u8),
    raw: []const u8,
    plan: Plan,
    report: *FstabReport,
) !void {
    // Only the line terminator is trimmed for parsing; `raw` -- terminator
    // included -- is what gets copied. Field offsets index into `body`, which
    // is a prefix of `raw`, so they address `raw`'s bytes directly.
    const body = std.mem.trimEnd(u8, raw, "\r\n");
    var fields = FieldIterator{ .bytes = body };
    const spec = fields.next() orelse return out.appendSlice(raw);
    if (spec.text[0] == '#') return out.appendSlice(raw);

    const mount_field = fields.next();
    const type_field = fields.next();

    // Is this the entry that mounts the rebuilt root? Decided by the mount
    // point alone, so it holds however the entry names its device -- a tagged
    // UUID, a `/dev` path, anything -- since only the type rewrite depends on
    // it and the root is always mounted at "/".
    var is_root_mount = false;
    if (mount_field) |mount_point| {
        const decoded = try unescapeFstabField(allocator, mount_point.text);
        defer allocator.free(decoded);
        for (plan.filesystems) |filesystem| {
            const merged_at = filesystem.merged_at orelse continue;
            // An exact match only. A `/boot/efi` entry must survive `/boot`
            // being merged when the ESP itself is still a partition, so a
            // prefix rule would delete a mount the image needs.
            if (!std.mem.eql(u8, merged_at, decoded)) continue;
            report.entries_dropped += 1;
            return;
        }
        is_root_mount = std.mem.eql(u8, decoded, "/");
    }

    // Splice 1 (optional): the tagged identifier in the first field.
    var id_start: ?usize = null;
    var id_len: usize = 0;
    var id_replacement: []const u8 = "";
    if (parseTaggedSpec(spec.text)) |tagged| {
        if (plan.find(tagged.kind, tagged.value)) |filesystem| {
            if (filesystem.merged_at != null) {
                // The filesystem this entry names does not exist any more,
                // wherever the entry proposed to mount it.
                report.entries_dropped += 1;
                return;
            }
            if (isRetired(filesystem, tagged.kind)) {
                if (filesystem.after.get(tagged.kind)) |replacement| {
                    id_start = spec.start + tagged.value_offset;
                    id_len = tagged.value.len;
                    id_replacement = replacement;
                } else {
                    report.entries_unresolved += 1;
                }
            }
        }
    }

    // Splice 2 (optional): the filesystem-type third field, but only on the
    // root entry, only when a root kind is known, and only when the imported
    // type is a recognized ext4/xfs value that differs from it. An unrelated
    // type (btrfs, swap, auto) parses to null and is left exactly as it was.
    var type_start: ?usize = null;
    var type_len: usize = 0;
    var type_replacement: []const u8 = "";
    if (is_root_mount) {
        if (plan.rootType()) |root_kind| {
            if (type_field) |tf| {
                if (FilesystemType.parse(tf.text)) |imported| {
                    if (imported != root_kind) {
                        type_start = tf.start;
                        type_len = tf.text.len;
                        type_replacement = root_kind.name();
                    }
                }
            }
        }
    }

    if (id_start == null and type_start == null) return out.appendSlice(raw);

    // Apply the splices in ascending offset order -- the identifier is in field
    // one, the type in field three, so identifier always precedes type -- and
    // copy every other byte (spacing, field padding, comments, the terminator)
    // through untouched.
    var pos: usize = 0;
    if (id_start) |start| {
        try out.appendSlice(raw[pos..start]);
        try out.appendSlice(id_replacement);
        pos = start + id_len;
        report.entries_rewritten += 1;
    }
    if (type_start) |start| {
        try out.appendSlice(raw[pos..start]);
        try out.appendSlice(type_replacement);
        pos = start + type_len;
        report.types_rewritten += 1;
    }
    try out.appendSlice(raw[pos..]);
}

const TaggedSpec = struct {
    kind: Kind,
    /// Offset of the value within the spec field.
    value_offset: usize,
    value: []const u8,
};

fn parseTaggedSpec(spec: []const u8) ?TaggedSpec {
    inline for (comptime std.enums.values(Kind)) |kind| {
        const prefix = comptime kind.tag() ++ "=";
        // `PARTUUID=` cannot be confused with `UUID=`: the prefix is matched
        // from the start of the field, so the longer tag never shadows.
        if (std.mem.startsWith(u8, spec, prefix) and spec.len > prefix.len) {
            return .{
                .kind = kind,
                .value_offset = prefix.len,
                .value = spec[prefix.len..],
            };
        }
    }
    return null;
}

/// Decodes the octal escapes `mount(8)` uses for characters that would
/// otherwise end a field. Only used to compare a mount point against a plan;
/// the original bytes are what gets written back.
fn unescapeFstabField(allocator: Allocator, field: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var index: usize = 0;
    while (index < field.len) {
        if (field[index] == '\\' and index + 3 < field.len) {
            if (std.fmt.parseInt(u8, field[index + 1 ..][0..3], 8)) |byte| {
                try out.append(byte);
                index += 4;
                continue;
            } else |_| {}
        }
        try out.append(field[index]);
        index += 1;
    }
    return out.toOwnedSlice();
}

/// How much `rewriteConfig` changed, split so a caller can report a
/// filesystem-type correction distinctly from an identifier replacement.
pub const ConfigReport = struct {
    /// Every value replaced -- retired identifiers and `rootfstype=`
    /// corrections both. This is what "did the file change" turns on.
    references: usize = 0,
    /// The subset of `references` that were `rootfstype=` type corrections.
    rootfstype_rewritten: usize = 0,
};

/// Rewrites retired UUIDs, and a stale root `rootfstype=`, in a bootloader
/// configuration in place, returning owned bytes. Every byte that is not part
/// of a replaced value is copied through unchanged, which is what keeps a
/// distro `grub.cfg`'s menu structure, its generated-file banners and its
/// shell quoting intact.
///
/// A retired identifier is replaced wherever it appears as a whole token,
/// rather than only after the specific spellings `root=UUID=` and
/// `search --fs-uuid`. Those two are what the issue named, but the same
/// value also turns up in `resume=`, in `--hint`, in `rd.luks.uuid=` and in
/// comments, and every one of them is equally stale. Restricting the rewrite
/// to two syntaxes would leave the rest for the verification pass to reject.
///
/// A stale filesystem *type* is corrected only through the one syntax that
/// unambiguously names the root's kind: a `rootfstype=<ext4|xfs>` kernel
/// parameter that disagrees with the kind the root now is. That is the extent
/// of the filesystem-type rewrite here, and it is deliberate.
///
/// GRUB's `search` selects a device by `--fs-uuid`, `--label` or `--file` --
/// all identifiers, handled above -- and has no filesystem-*type* hint to
/// rewrite; the investigation the issue asked for found none. The filesystem
/// type does appear in a `grub.cfg` as `insmod ext2`/`insmod xfs`, but those
/// name the module GRUB itself uses to *read* a partition (usually `/boot` or
/// the ESP, not the converted root), so rewriting them toward the root's kind
/// would as often break booting as fix it. A bare `ext4`/`xfs` word could also
/// be a menu title, a comment or part of a path. Both are therefore left
/// untouched rather than rewritten by broad textual replacement: a genuinely
/// stale one is caught by the verification pass and reported for the
/// `unsafe_chroot` escape hatch, never silently corrupted.
///
/// Labels are deliberately not rewritten here: a label is an arbitrary word,
/// and replacing every occurrence of `boot` or `EFI` in a shell-syntax
/// configuration would corrupt it.
pub fn rewriteConfig(
    allocator: Allocator,
    original: []const u8,
    plan: Plan,
    report: *ConfigReport,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    try out.ensureTotalCapacity(original.len);

    var index: usize = 0;
    while (index < original.len) {
        // The `rootfstype=` rewrite carries its own word-boundary rule (its key
        // is not hexadecimal, so the identifier token boundary below does not
        // apply), so it is tried first and independently.
        if (findRootfstypeRewrite(plan, original, index)) |rewrite| {
            try out.appendSlice(rootfstype_key);
            try out.appendSlice(rewrite.replacement);
            index += rewrite.consumed;
            report.references += 1;
            report.rootfstype_rewritten += 1;
            continue;
        }
        if (tokenStartsAt(original, index)) {
            if (findConfigReplacement(plan, original, index)) |match| {
                try out.appendSlice(match.replacement);
                index += match.length;
                report.references += 1;
                continue;
            }
        }
        try out.append(original[index]);
        index += 1;
    }
    return out.toOwnedSlice();
}

const rootfstype_key = "rootfstype=";

const RootfstypeRewrite = struct {
    replacement: []const u8,
    /// Bytes of `original` this consumes: the whole `rootfstype=<value>` run,
    /// since the key is re-emitted verbatim and only the value changes.
    consumed: usize,
};

/// Matches a `rootfstype=<ext4|xfs>` assignment at `index` whose value is a
/// recognized type differing from the root's actual kind, and returns the
/// corrected value. Returns null -- leaving the bytes untouched -- when no root
/// kind is known, the key does not start here at a genuine word boundary, or
/// the value is unrecognized or already correct.
fn findRootfstypeRewrite(plan: Plan, bytes: []const u8, index: usize) ?RootfstypeRewrite {
    const root_kind = plan.rootType() orelse return null;
    // A real word boundary for a non-hexadecimal key: start of file, or a
    // command-line separator (whitespace or a shell quote) immediately before.
    if (index != 0 and !isCmdlineSeparator(bytes[index - 1])) return null;
    if (!std.mem.startsWith(u8, bytes[index..], rootfstype_key)) return null;

    const value_start = index + rootfstype_key.len;
    var value_end = value_start;
    while (value_end < bytes.len and isFilesystemTypeByte(bytes[value_end])) value_end += 1;
    const value = bytes[value_start..value_end];

    const imported = FilesystemType.parse(value) orelse return null;
    if (imported == root_kind) return null;
    return .{ .replacement = root_kind.name(), .consumed = rootfstype_key.len + value.len };
}

/// A command-line token separator: what precedes a standalone kernel parameter
/// like `rootfstype=`. Whitespace, or a shell quote a `grub.cfg` wraps the
/// parameter list in.
fn isCmdlineSeparator(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r' or byte == '"' or byte == '\'';
}

/// The alphabet of a filesystem-type word: `mount`/the kernel spell every type
/// name in lowercase ASCII letters and digits, so the value ends at the first
/// byte outside that set (a space, a quote, a newline).
fn isFilesystemTypeByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte);
}

const ConfigMatch = struct {
    length: usize,
    replacement: []const u8,
};

fn findConfigReplacement(plan: Plan, bytes: []const u8, index: usize) ?ConfigMatch {
    for (plan.filesystems) |filesystem| {
        inline for (comptime std.enums.values(Kind)) |kind| {
            if (comptime kind.isUuid()) {
                if (isRetired(filesystem, kind)) {
                    const before = filesystem.before.get(kind).?;
                    if (filesystem.after.get(kind)) |after| {
                        if (matchesAt(bytes, index, before, true)) {
                            return .{ .length = before.len, .replacement = after };
                        }
                    }
                }
            }
        }
    }
    return null;
}

fn tokenStartsAt(bytes: []const u8, index: usize) bool {
    return index == 0 or !isIdentifierByte(bytes[index - 1]);
}

/// Hexadecimal digits and the separator, which is exactly the alphabet of a
/// UUID and of a FAT volume serial.
fn isIdentifierByte(byte: u8) bool {
    return std.ascii.isHex(byte) or byte == '-';
}

/// Whether `needle` occurs at `index`, case-insensitively.
///
/// `require_boundaries` distinguishes the rewriter from the verification
/// pass. The rewriter only ever replaces a whole token, because splicing a
/// new UUID into the middle of some longer hexadecimal run would corrupt
/// whatever that run is. The verification pass asks the opposite question --
/// does this stale value survive anywhere at all -- and a full 36-character
/// UUID is specific enough that an occurrence inside a longer token is a
/// reference to it rather than a coincidence. A FAT volume serial is only
/// nine characters, so for those the pass keeps the boundary requirement:
/// `1234-ABCD` inside a longer hex run is not a reference to the volume.
fn matchesAt(bytes: []const u8, index: usize, needle: []const u8, require_boundaries: bool) bool {
    if (index + needle.len > bytes.len) return false;
    if (!std.ascii.eqlIgnoreCase(bytes[index..][0..needle.len], needle)) return false;
    if (!require_boundaries) return true;
    if (!tokenStartsAt(bytes, index)) return false;
    const end = index + needle.len;
    return end == bytes.len or !isIdentifierByte(bytes[end]);
}

/// One retired identifier the verification pass looks for.
const Retired = struct {
    kind: Kind,
    value: []const u8,

    /// Short identifiers are matched as whole tokens only; see `matchesAt`.
    fn requiresBoundaries(self: Retired) bool {
        return self.value.len < canonical_uuid_bytes;
    }
};

/// Reads every file the pass covers and reports any surviving occurrence of
/// a retired identifier.
///
/// Labels are not searched for. `LABEL=` entries for a merged filesystem are
/// dropped from fstab by the rewriter, and searching a whole ESP for the
/// word `EFI` would fail every build for reasons that have nothing to do
/// with the rebuild.
fn verify(
    allocator: Allocator,
    tree: *const root_tree.RootTree,
    plan: Plan,
    scope: Scope,
    report: *Report,
    diagnostic: ?*Diagnostic,
) !void {
    var retired = std.array_list.Managed(Retired).init(allocator);
    defer retired.deinit();
    for (plan.filesystems) |filesystem| {
        inline for (comptime std.enums.values(Kind)) |kind| {
            if (comptime kind.isUuid()) {
                if (isRetired(filesystem, kind)) {
                    try retired.append(.{ .kind = kind, .value = filesystem.before.get(kind).? });
                }
            }
        }
    }
    if (retired.items.len == 0) return;

    // A window large enough that any identifier straddling two reads is
    // still contiguous once the tail of the previous read is carried over.
    const window: usize = 64 * 1024;
    const carry = max_identifier_bytes - 1;
    const buffer = try allocator.alloc(u8, window + carry);
    defer allocator.free(buffer);

    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const node = tree.nodeView(index);
        if (node.kind != .file) continue;
        if (!isVerificationTarget(node.path, scope)) continue;
        report.verified_files += 1;
        try verifyFile(tree, node.path, retired.items, buffer, carry, report, diagnostic);
    }
}

fn verifyFile(
    tree: *const root_tree.RootTree,
    path: []const u8,
    retired: []const Retired,
    buffer: []u8,
    carry: usize,
    report: *Report,
    diagnostic: ?*Diagnostic,
) !void {
    // `file_offset` is the absolute offset of `buffer[0]`.
    var file_offset: u64 = 0;
    var held: usize = 0;
    while (true) {
        const read = try tree.readNodeContent(path, buffer[held..], file_offset + held);
        const filled = held + read;
        if (filled == 0) return;
        const final = read == 0;
        const chunk = buffer[0..filled];

        // Every start position is examined exactly once. On a non-final
        // chunk the last `carry` positions are deferred rather than tested
        // short: `carry` is at least the longest identifier, so each of them
        // reappears -- whole, this time -- in the next chunk. Testing them
        // here as well would count one occurrence twice.
        const limit = if (final) filled else filled -| carry;
        var at: usize = 0;
        while (at < limit) : (at += 1) {
            for (retired) |item| {
                if (!matchesAt(chunk, at, item.value, item.requiresBoundaries())) continue;
                report.stale_references += 1;
                if (diagnostic) |sink| sink.record(item.kind, item.value, path, file_offset + at);
                break;
            }
        }

        if (final) return;
        const keep = @min(carry, filled);
        std.mem.copyForwards(u8, buffer[0..keep], chunk[filled - keep ..]);
        file_offset += filled - keep;
        held = keep;
    }
}

/// Written with explicit escapes rather than as a multiline literal because
/// the tabs, the trailing spaces, the CRLF and the missing final newline are
/// the whole point: this is what "byte for byte" has to mean.
const untouched_fstab =
    "# /etc/fstab: static file system information.\n" ++
    "#\n" ++
    "# <file system> <mount point>   <type>  <options>       <dump>  <pass>\r\n" ++
    "   # an indented comment\n" ++
    "\n" ++
    "tmpfs\t\t/tmp\t\ttmpfs\tdefaults,noatime\t0\t0   \n" ++
    "//server/share  /mnt/share  cifs  credentials=/etc/creds,_netdev  0  0\n" ++
    "/dev/mapper/vg-swap none            swap    sw              0       0\n" ++
    "UUID=99999999-9999-9999-9999-999999999999 /data ext4 defaults 0 2\n" ++
    "/dev/sdb1 /mnt/scratch ext4 noauto 0 0";

test "an untouched fstab survives a rewrite byte for byte" {
    const allocator = std.testing.allocator;
    // Both with an empty plan and with a plan that retires an identifier
    // this fstab never mentions: neither may perturb a single byte.
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = test_boot_uuid },
        .after = .{ .filesystem_uuid = test_root_uuid },
        .merged_at = "/boot",
    }};
    const plans = [_]Plan{ .{}, .{ .filesystems = &filesystems } };
    for (plans) |plan| {
        var report = FstabReport{};
        const rewritten = try rewriteFstab(allocator, untouched_fstab, plan, &report);
        defer allocator.free(rewritten);
        try std.testing.expectEqualStrings(untouched_fstab, rewritten);
        try std.testing.expectEqualSlices(u8, untouched_fstab, rewritten);
        try std.testing.expectEqual(@as(usize, 0), report.entries_rewritten);
        try std.testing.expectEqual(@as(usize, 0), report.entries_dropped);
        try std.testing.expectEqual(@as(usize, 0), report.entries_unresolved);
    }
}

test "fstab rewriting replaces only the identifier and drops merged filesystems" {
    const allocator = std.testing.allocator;
    const original =
        \\# keep me exactly as I am
        \\UUID=11111111-1111-1111-1111-111111111111 /               ext4    errors=remount-ro 0       1
        \\UUID=22222222-2222-2222-2222-222222222222 /boot           ext4    defaults        0       2
        \\UUID=5A56-4D49  /boot/efi       vfat    umask=0077      0       1
        \\PARTUUID=33333333-3333-3333-3333-333333333333 /srv        xfs     defaults        0       2
        \\LABEL=data      /data           ext4    defaults        0       2
        \\tmpfs           /tmp            tmpfs   defaults        0       0
        \\
    ;
    const filesystems = [_]Filesystem{
        .{
            .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
        },
        .{
            .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
            .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
            .merged_at = "/boot",
        },
        .{
            .before = .{ .filesystem_uuid = "5A56-4D49" },
            .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
            .merged_at = "/boot/efi",
        },
    };
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);

    const expected =
        \\# keep me exactly as I am
        \\UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa /               ext4    errors=remount-ro 0       1
        \\PARTUUID=33333333-3333-3333-3333-333333333333 /srv        xfs     defaults        0       2
        \\LABEL=data      /data           ext4    defaults        0       2
        \\tmpfs           /tmp            tmpfs   defaults        0       0
        \\
    ;
    try std.testing.expectEqualStrings(expected, rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.entries_rewritten);
    try std.testing.expectEqual(@as(usize, 2), report.entries_dropped);
}

test "an fstab entry is dropped by its mount point even when it names a device" {
    const allocator = std.testing.allocator;
    const original =
        \\/dev/sda2       /boot   ext4    defaults        0       2
        \\/dev/sda1       /boot/efi       vfat    umask=0077      0       1
        \\/dev/sda4       /home   ext4    defaults        0       2
        \\
    ;
    const filesystems = [_]Filesystem{
        .{
            .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
            .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
            .merged_at = "/boot",
        },
    };
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);

    // The ESP entry survives: `/boot` being merged says nothing about a
    // partition that is still a partition.
    const expected =
        \\/dev/sda1       /boot/efi       vfat    umask=0077      0       1
        \\/dev/sda4       /home   ext4    defaults        0       2
        \\
    ;
    try std.testing.expectEqualStrings(expected, rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.entries_dropped);
}

test "an escaped mount point still matches the merge that removed it" {
    const allocator = std.testing.allocator;
    const original = "UUID=22222222-2222-2222-2222-222222222222 /boot\\040spare ext4 defaults 0 2\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
        .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
        .merged_at = "/boot spare",
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings("", rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.entries_dropped);
}

test "an fstab entry with no replacement is left alone and reported" {
    const allocator = std.testing.allocator;
    const original = "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.entries_unresolved);
    try std.testing.expectEqual(@as(usize, 0), report.entries_rewritten);
}

test "a case-different fstab identifier is still recognized" {
    const allocator = std.testing.allocator;
    const original = "UUID=ABCDEF01-1111-1111-1111-111111111111 / ext4 defaults 0 1\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "abcdef01-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa / ext4 defaults 0 1\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 1), report.entries_rewritten);
}

test "grub configuration is rewritten in place and keeps its structure" {
    const allocator = std.testing.allocator;
    // Tabs and quoting are written with escapes so the assertion below is a
    // statement about bytes, which is what a bootloader parses.
    const original = "# DO NOT EDIT THIS FILE\n" ++
        "set default=\"0\"\n" ++
        "menuentry 'Ubuntu' --class ubuntu {\n" ++
        "\tsearch --no-floppy --fs-uuid --set=root 22222222-2222-2222-2222-222222222222\n" ++
        "\tlinux\t/vmlinuz-6.1 root=UUID=11111111-1111-1111-1111-111111111111 ro quiet\n" ++
        "\tinitrd\t/initrd.img-6.1\n" ++
        "}\n" ++
        "menuentry 'Windows' {\n" ++
        "\tsearch --fs-uuid --set=root 5A56-4D49\n" ++
        "\tchainloader /EFI/Microsoft/Boot/bootmgfw.efi\n" ++
        "}\n";
    const filesystems = [_]Filesystem{
        .{
            .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
            .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .merged_at = "/boot",
        },
        .{
            .before = .{ .filesystem_uuid = "5A56-4D49" },
            .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .merged_at = "/boot/efi",
        },
    };
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);

    const expected = "# DO NOT EDIT THIS FILE\n" ++
        "set default=\"0\"\n" ++
        "menuentry 'Ubuntu' --class ubuntu {\n" ++
        "\tsearch --no-floppy --fs-uuid --set=root 11111111-1111-1111-1111-111111111111\n" ++
        "\tlinux\t/vmlinuz-6.1 root=UUID=11111111-1111-1111-1111-111111111111 ro quiet\n" ++
        "\tinitrd\t/initrd.img-6.1\n" ++
        "}\n" ++
        "menuentry 'Windows' {\n" ++
        "\tsearch --fs-uuid --set=root 11111111-1111-1111-1111-111111111111\n" ++
        "\tchainloader /EFI/Microsoft/Boot/bootmgfw.efi\n" ++
        "}\n";
    try std.testing.expectEqualStrings(expected, rewritten);
    try std.testing.expectEqual(@as(usize, 2), config.references);
}

test "a retired identifier inside a longer token is not spliced" {
    const allocator = std.testing.allocator;
    // Deliberately glued to more hexadecimal: replacing here would corrupt
    // whatever the longer run is.
    const original = "set x=a22222222-2222-2222-2222-2222222222220\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .merged_at = "/boot",
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), config.references);
}

test "a plan with nothing retired changes nothing" {
    const allocator = std.testing.allocator;
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
    }};
    const plan = Plan{ .filesystems = &filesystems };
    try plan.validate();
    try std.testing.expect(!plan.retiresAnything());

    const original = "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n";
    var report = FstabReport{};
    const rewritten = try rewriteFstab(allocator, original, plan, &report);
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
}

test "an ext4 root converted to xfs has its fstab type field corrected" {
    const allocator = std.testing.allocator;
    // The identifier is unchanged (the root keeps its UUID through the
    // rebuild); only the third field is stale after ext4 -> xfs.
    const original = "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "UUID=11111111-1111-1111-1111-111111111111 / xfs defaults 0 1\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 0), report.entries_rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.types_rewritten);
}

test "an xfs root and its identifier are corrected together in one entry" {
    const allocator = std.testing.allocator;
    // Both fields are stale: the UUID was retired and the type was ext4. The
    // two splices land in ascending offset order and every byte between and
    // around them -- the tab padding -- is preserved.
    const original = "UUID=22222222-2222-2222-2222-222222222222\t/\text4\tdefaults\t0 1\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
        .after = .{ .filesystem_uuid = "33333333-3333-3333-3333-333333333333" },
        .root_filesystem_type = .xfs,
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "UUID=33333333-3333-3333-3333-333333333333\t/\txfs\tdefaults\t0 1\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 1), report.entries_rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.types_rewritten);
}

test "an ext4 root that stays ext4 keeps its fstab bytes exactly" {
    const allocator = std.testing.allocator;
    // The default path: the kind is threaded through and it is still ext4, so
    // the type field must not be touched even though a root kind is known.
    const original = "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .ext4,
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), report.types_rewritten);
}

test "the fstab type rewrite preserves comments alignment and unrelated mounts" {
    const allocator = std.testing.allocator;
    // A realistic fstab: a comment, the root on aligned columns, a separate
    // ext4 /home that must stay ext4, and a btrfs mount whose type is an
    // unrelated word the rewrite must not recognize. Only the root's `ext4`
    // becomes `xfs`; every other byte -- the column spacing, the comment, the
    // trailing blank line -- is identical.
    const original =
        "# /etc/fstab: static file system information.\n" ++
        "UUID=11111111-1111-1111-1111-111111111111   /       ext4    defaults        0 1\n" ++
        "UUID=44444444-4444-4444-4444-444444444444   /home   ext4    defaults        0 2\n" ++
        "UUID=55555555-5555-5555-5555-555555555555   /data   btrfs   defaults        0 2\n" ++
        "\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    const expected =
        "# /etc/fstab: static file system information.\n" ++
        "UUID=11111111-1111-1111-1111-111111111111   /       xfs    defaults        0 1\n" ++
        "UUID=44444444-4444-4444-4444-444444444444   /home   ext4    defaults        0 2\n" ++
        "UUID=55555555-5555-5555-5555-555555555555   /data   btrfs   defaults        0 2\n" ++
        "\n";
    try std.testing.expectEqualStrings(expected, rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.types_rewritten);
}

test "a merged mount is dropped even when a root type rewrite is active" {
    const allocator = std.testing.allocator;
    // The root converts to xfs and /boot is merged away in the same plan. The
    // merged entry must still be deleted, not type-rewritten (it is not the
    // root mount), and the root's type is corrected.
    const original =
        "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n" ++
        "UUID=22222222-2222-2222-2222-222222222222 /boot ext4 defaults 0 2\n";
    const filesystems = [_]Filesystem{
        .{
            .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .root_filesystem_type = .xfs,
        },
        .{
            .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
            .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .merged_at = "/boot",
        },
    };
    var report = FstabReport{};
    const rewritten = try rewriteFstab(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &report,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "UUID=11111111-1111-1111-1111-111111111111 / xfs defaults 0 1\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 1), report.types_rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.entries_dropped);
}

test "a stale rootfstype on the kernel command line is corrected" {
    const allocator = std.testing.allocator;
    const original =
        "linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 rootfstype=ext4 ro\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 rootfstype=xfs ro\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 1), config.references);
    try std.testing.expectEqual(@as(usize, 1), config.rootfstype_rewritten);
}

test "a rootfstype already matching the root is left untouched" {
    const allocator = std.testing.allocator;
    const original = "GRUB_CMDLINE_LINUX=\"rootfstype=xfs quiet\"\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), config.references);
    try std.testing.expectEqual(@as(usize, 0), config.rootfstype_rewritten);
}

test "a rootfstype glued to a longer word is not a boundary and is left alone" {
    const allocator = std.testing.allocator;
    // `notrootfstype=ext4` is a different key; the boundary check must refuse
    // to treat its tail as a `rootfstype=` assignment.
    const original = "set notrootfstype=ext4\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), config.rootfstype_rewritten);
}

test "an unrelated rootfstype value is not rewritten toward the root kind" {
    const allocator = std.testing.allocator;
    // btrfs is not a kind this module writes; a `rootfstype=btrfs` is not the
    // stale-conversion case and must be left for the verification pass, never
    // rewritten to the root's kind.
    const original = "rootfstype=btrfs ro\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .root_filesystem_type = .xfs,
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), config.rootfstype_rewritten);
}

test "a config with no root kind threaded leaves rootfstype exactly as before" {
    const allocator = std.testing.allocator;
    // Backward compatibility: an older plan that never set a root kind must
    // behave as it always did and touch no `rootfstype=`.
    const original = "rootfstype=ext4 ro\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
        .after = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(original, rewritten);
    try std.testing.expectEqual(@as(usize, 0), config.rootfstype_rewritten);
}

test "a stale rootfstype and a retired identifier are both corrected in one line" {
    const allocator = std.testing.allocator;
    const original =
        "linux /vmlinuz root=UUID=22222222-2222-2222-2222-222222222222 rootfstype=ext4 ro\n";
    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = "22222222-2222-2222-2222-222222222222" },
        .after = .{ .filesystem_uuid = "33333333-3333-3333-3333-333333333333" },
        .root_filesystem_type = .xfs,
    }};
    var config = ConfigReport{};
    const rewritten = try rewriteConfig(
        allocator,
        original,
        .{ .filesystems = &filesystems },
        &config,
    );
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        "linux /vmlinuz root=UUID=33333333-3333-3333-3333-333333333333 rootfstype=xfs ro\n",
        rewritten,
    );
    try std.testing.expectEqual(@as(usize, 2), config.references);
    try std.testing.expectEqual(@as(usize, 1), config.rootfstype_rewritten);
}

test "a malformed plan is refused rather than matched loosely" {
    try std.testing.expectError(error.InvalidIdentifier, (Plan{
        .filesystems = &.{.{ .before = .{ .filesystem_uuid = "" } }},
    }).validate());
    try std.testing.expectError(error.InvalidRewritePath, (Plan{
        .filesystems = &.{.{
            .before = .{ .filesystem_uuid = "11111111-1111-1111-1111-111111111111" },
            .merged_at = "boot",
        }},
    }).validate());
    try std.testing.expectError(error.InvalidRewritePath, (Plan{
        .esp_roots = &.{"/boot/efi/"},
    }).validate());
}

const test_root_uuid = "11111111-1111-1111-1111-111111111111";
const test_boot_uuid = "22222222-2222-2222-2222-222222222222";

fn testPlan() Plan {
    const filesystems = struct {
        const value = [_]Filesystem{
            .{
                .before = .{ .filesystem_uuid = test_root_uuid },
                .after = .{ .filesystem_uuid = test_root_uuid },
            },
            .{
                .before = .{ .filesystem_uuid = test_boot_uuid },
                .after = .{ .filesystem_uuid = test_root_uuid },
                .merged_at = "/boot",
            },
        };
    };
    const roots = struct {
        const value = [_][]const u8{"/boot/efi"};
    };
    return .{ .filesystems = &filesystems.value, .esp_roots = &roots.value };
}

fn putTestFile(tree: *root_tree.RootTree, path: []const u8, bytes: []const u8) !void {
    try tree.putFileBytes(path, bytes, .{ .mode = 0o644 });
}

fn readTestFile(allocator: Allocator, tree: *root_tree.RootTree, path: []const u8) ![]u8 {
    return tree.readFileAlloc(allocator, path, max_config_bytes);
}

test "apply rewrites a tree and accepts it once nothing stale is left" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();

    try putTestFile(&tree, "etc/fstab",
        \\# comment kept verbatim
        \\UUID=11111111-1111-1111-1111-111111111111 /       ext4  defaults  0 1
        \\UUID=22222222-2222-2222-2222-222222222222 /boot   ext4  defaults  0 2
        \\tmpfs   /tmp    tmpfs   defaults        0       0
        \\
    );
    try putTestFile(&tree, "boot/grub/grub.cfg",
        \\search --fs-uuid --set=root 22222222-2222-2222-2222-222222222222
        \\linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 ro
        \\
    );
    try putTestFile(
        &tree,
        "boot/efi/EFI/ubuntu/grub.cfg",
        "search.fs_uuid 22222222-2222-2222-2222-222222222222 root\n",
    );

    var diagnostic = Diagnostic{};
    const report = try apply(allocator, &tree, testPlan(), .rewrite_and_verify, &diagnostic);
    try std.testing.expect(diagnostic.stale == null);
    try std.testing.expectEqual(@as(usize, 0), report.stale_references);
    try std.testing.expectEqual(@as(usize, 1), report.fstab_entries_dropped);
    try std.testing.expectEqual(@as(usize, 0), report.fstab_entries_rewritten);
    try std.testing.expectEqual(@as(usize, 2), report.config_files_rewritten);
    try std.testing.expectEqual(@as(usize, 2), report.config_references_rewritten);
    try std.testing.expectEqual(@as(usize, 3), report.verified_files);

    const fstab = try readTestFile(allocator, &tree, "etc/fstab");
    defer allocator.free(fstab);
    try std.testing.expectEqualStrings(
        \\# comment kept verbatim
        \\UUID=11111111-1111-1111-1111-111111111111 /       ext4  defaults  0 1
        \\tmpfs   /tmp    tmpfs   defaults        0       0
        \\
    , fstab);

    const grub = try readTestFile(allocator, &tree, "boot/grub/grub.cfg");
    defer allocator.free(grub);
    try std.testing.expectEqualStrings(
        \\search --fs-uuid --set=root 11111111-1111-1111-1111-111111111111
        \\linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 ro
        \\
    , grub);
}

test "apply performs a root filesystem type-only rewrite" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();

    try putTestFile(
        &tree,
        "etc/fstab",
        "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n",
    );
    try putTestFile(
        &tree,
        "boot/grub/grub.cfg",
        "linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 rootfstype=ext4 ro\n",
    );

    const filesystems = [_]Filesystem{.{
        .before = .{ .filesystem_uuid = test_root_uuid },
        .after = .{ .filesystem_uuid = test_root_uuid },
        .root_filesystem_type = .xfs,
    }};
    const report = try apply(
        allocator,
        &tree,
        .{ .filesystems = &filesystems },
        .rewrite_and_verify,
        null,
    );
    try std.testing.expectEqual(@as(usize, 0), report.retired_identifiers);
    try std.testing.expectEqual(@as(usize, 1), report.fstab_types_rewritten);
    try std.testing.expectEqual(@as(usize, 1), report.config_rootfstype_rewritten);

    const fstab = try readTestFile(allocator, &tree, "etc/fstab");
    defer allocator.free(fstab);
    try std.testing.expectEqualStrings(
        "UUID=11111111-1111-1111-1111-111111111111 / xfs defaults 0 1\n",
        fstab,
    );

    const grub = try readTestFile(allocator, &tree, "boot/grub/grub.cfg");
    defer allocator.free(grub);
    try std.testing.expectEqualStrings(
        "linux /vmlinuz root=UUID=11111111-1111-1111-1111-111111111111 rootfstype=xfs ro\n",
        grub,
    );
}

test "apply fails the build and names the file holding a stale identifier" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();

    try putTestFile(&tree, "etc/fstab", "UUID=11111111-1111-1111-1111-111111111111 / ext4 defaults 0 1\n");
    // `core.img` is not text and is not rewritten, which is exactly why the
    // verification pass has to read it. Uppercase, because a stale
    // identifier that differs only in case is still stale.
    try putTestFile(
        &tree,
        "boot/grub/i386-pc/core.img",
        "\x00\x00search --fs-uuid 22222222-2222-2222-2222-222222222222\x00",
    );

    var diagnostic = Diagnostic{};
    try std.testing.expectError(
        error.StaleFilesystemIdentifier,
        apply(allocator, &tree, testPlan(), .rewrite_and_verify, &diagnostic),
    );
    const stale = diagnostic.stale orelse return error.MissingDiagnostic;
    try std.testing.expectEqualStrings("boot/grub/i386-pc/core.img", stale.path());
    try std.testing.expectEqualStrings(test_boot_uuid, stale.identifier());
    try std.testing.expectEqual(Kind.filesystem_uuid, stale.kind);
    try std.testing.expectEqual(@as(u64, 19), stale.offset);

    var message: [Stale.max_message_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/boot/grub/i386-pc/core.img still names the retired UUID " ++
            test_boot_uuid ++ " at offset 19",
        try stale.describe(&message),
    );
}

test "verification is case-insensitive and sees an identifier inside a longer token" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();

    // Both evasions at once: uppercase hex, and glued to more hex so the
    // rewriter deliberately leaves it alone.
    try putTestFile(
        &tree,
        "etc/crypttab",
        "cryptswap UUID=ff22222222-2222-2222-2222-222222222222ff none swap\n",
    );

    var diagnostic = Diagnostic{};
    try std.testing.expectError(
        error.StaleFilesystemIdentifier,
        apply(allocator, &tree, testPlan(), .rewrite_and_verify, &diagnostic),
    );
    const stale = diagnostic.stale orelse return error.MissingDiagnostic;
    try std.testing.expectEqualStrings("etc/crypttab", stale.path());
}

test "a stale identifier split across two read windows is still found" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();

    // Straddles the 64 KiB window boundary by design: a scanner that looked
    // at each read in isolation would miss this and pass a broken image.
    const window: usize = 64 * 1024;
    const filler = try allocator.alloc(u8, window - 10);
    defer allocator.free(filler);
    @memset(filler, 'z');
    const contents = try std.fmt.allocPrint(allocator, "{s}{s} tail\n", .{ filler, test_boot_uuid });
    defer allocator.free(contents);
    try putTestFile(&tree, "boot/grub/fonts/unicode.pf2", contents);

    var diagnostic = Diagnostic{};
    try std.testing.expectError(
        error.StaleFilesystemIdentifier,
        apply(allocator, &tree, testPlan(), .rewrite_and_verify, &diagnostic),
    );
    const stale = diagnostic.stale orelse return error.MissingDiagnostic;
    try std.testing.expectEqualStrings("boot/grub/fonts/unicode.pf2", stale.path());
    try std.testing.expectEqual(@as(u64, window - 10), stale.offset);
}

test "rewrite_only reports what it could not fix instead of failing" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();
    try putTestFile(&tree, "boot/grub/grubenv", "prev_boot=" ++ test_boot_uuid ++ "\n");

    var diagnostic = Diagnostic{};
    const report = try apply(allocator, &tree, testPlan(), .rewrite_only, &diagnostic);
    try std.testing.expectEqual(@as(usize, 1), report.stale_references);
    try std.testing.expect(diagnostic.stale != null);

    // And `.off` is exactly that: no reads, no rewrites, no verdict.
    const untouched = try apply(allocator, &tree, testPlan(), .off, &diagnostic);
    try std.testing.expectEqual(@as(usize, 0), untouched.verified_files);
    try std.testing.expectEqual(@as(usize, 0), untouched.retired_identifiers);
}

test "files outside the scanned locations are neither rewritten nor verified" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();
    // A stale identifier inside an initramfs is neither rewritable nor
    // readable in general, so `/boot` at large is out of scope; only the
    // bootloader's own directories and the ESP are in it.
    try putTestFile(&tree, "boot/initrd.img-6.1", "resume=UUID=" ++ test_boot_uuid ++ "\n");
    try putTestFile(&tree, "usr/share/doc/notes.txt", test_boot_uuid);

    var diagnostic = Diagnostic{};
    const report = try apply(allocator, &tree, testPlan(), .rewrite_and_verify, &diagnostic);
    try std.testing.expectEqual(@as(usize, 0), report.verified_files);
    try std.testing.expectEqual(@as(usize, 0), report.stale_references);
}

test "a tree that is itself an ESP is scanned without a path prefix to name it" {
    const allocator = std.testing.allocator;

    // The same content, once as a subtree of a root filesystem and once as
    // the whole of a captured ESP written to its own partition. `esp_roots`
    // can express the first and cannot express the second: it names an
    // absolute path, and a partition's own root has no prefix. Both must
    // reach the same file.
    var merged = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer merged.deinit();
    try putTestFile(&merged, "boot/efi/EFI/vendor/grub.cfg", "root=UUID=" ++ test_boot_uuid ++ "\n");

    var standalone = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer standalone.deinit();
    try putTestFile(&standalone, "EFI/vendor/grub.cfg", "root=UUID=" ++ test_boot_uuid ++ "\n");

    const merged_report = try apply(allocator, &merged, testPlan(), .rewrite_and_verify, null);

    var esp_plan = testPlan();
    esp_plan.esp_roots = &.{};
    esp_plan.tree_is_esp = true;
    const standalone_report = try apply(allocator, &standalone, esp_plan, .rewrite_and_verify, null);

    try std.testing.expectEqual(
        merged_report.config_references_rewritten,
        standalone_report.config_references_rewritten,
    );
    try std.testing.expect(standalone_report.config_references_rewritten > 0);
    try std.testing.expectEqual(@as(usize, 0), standalone_report.stale_references);

    const rewritten = try readTestFile(allocator, &standalone, "EFI/vendor/grub.cfg");
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings("root=UUID=" ++ test_root_uuid ++ "\n", rewritten);
}

test "without the ESP flag a standalone ESP tree keeps its stale identifiers" {
    const allocator = std.testing.allocator;
    var tree = root_tree.RootTree.initMemory(allocator, std.testing.io, .{});
    defer tree.deinit();
    try putTestFile(&tree, "EFI/vendor/grub.cfg", "root=UUID=" ++ test_boot_uuid ++ "\n");

    // This is the failure the flag exists to prevent, pinned so that a
    // change making `esp_roots` reach a partition root does not pass
    // silently: the plan says the ESP lives at `/boot/efi` in some *other*
    // tree, so nothing here is in scope and the file survives untouched.
    const report = try apply(allocator, &tree, testPlan(), .rewrite_and_verify, null);
    try std.testing.expectEqual(@as(usize, 0), report.config_references_rewritten);

    const kept = try readTestFile(allocator, &tree, "EFI/vendor/grub.cfg");
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("root=UUID=" ++ test_boot_uuid ++ "\n", kept);
}

test "identifier text matches what blkid and an fstab spell" {
    // The ext4 superblock's own byte order, not GPT's mixed-endian one.
    var uuid_buffer: [canonical_uuid_bytes]u8 = undefined;
    const uuid = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    try std.testing.expectEqualStrings(
        "01234567-89ab-cdef-fedc-ba9876543210",
        formatFilesystemUuid(&uuid_buffer, &uuid),
    );

    var serial_buffer: [fat_serial_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "5A56-4D49",
        formatFatVolumeSerial(&serial_buffer, 0x5A56_4D49),
    );

    try std.testing.expectEqualStrings("root", trimLabel("root\x00\x00\x00").?);
    try std.testing.expectEqualStrings("EFI", trimLabel("EFI        ").?);
    try std.testing.expect(trimLabel("\x00\x00\x00") == null);
    try std.testing.expect(trimLabel("           ") == null);
}
