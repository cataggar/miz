//! What both executors need to know about relabelling a target root, in one
//! place so the host, the privileged worker and the guest agent cannot drift.
//!
//! Nothing here reads a filesystem. It is the shape of the operation -- where
//! the tool lives, where the policy lives, what the command line is -- so that
//! the host can refuse a request the target cannot satisfy, and the two
//! backends can carry out the same operation rather than two similar ones.

const std = @import("std");

/// Where the labelling tool is looked for inside the target root, in order.
/// `setfiles` rather than `restorecon` because it takes the file-contexts file
/// as an argument instead of resolving the active policy through libselinux,
/// which needs a loaded policy and a mounted selinuxfs -- neither of which
/// exists in an executor that is not running the target's kernel.
pub const setfiles_candidates = [_][]const u8{
    "/usr/sbin/setfiles",
    "/sbin/setfiles",
    "/usr/bin/setfiles",
};

/// The target's own SELinux configuration, which names the policy in use.
pub const config_path = "/etc/selinux/config";

/// The setting naming the mode the target's kernel is asked to boot in.
pub const mode_setting = "SELINUX";

/// The setting naming the policy the target loads.
pub const policy_setting = "SELINUXTYPE";

/// Upper bound on a `/etc/selinux/config` any side of this reads into memory.
/// The file is a handful of `KEY=value` lines a distro ships; anything past
/// this is not one. Named here so the host, the privileged worker and the
/// guest agent bound it the same way.
pub const max_config_bytes: usize = 64 * 1024;

/// Directories excluded from the walk, when they exist in the target root.
///
/// A relabel is about the files the image carries. These four are either
/// kernel interfaces the executor mounted for the run or state that exists
/// only while it runs, so labelling them would spend time on bytes that are
/// not in the image and, for the pseudo-filesystems, on inodes whose labels
/// are decided by the kernel that mounts them rather than by any policy file.
pub const excluded_directories = [_][]const u8{
    "/proc",
    "/sys",
    "/dev",
    "/run",
};

/// The longest policy name accepted. Long enough for any real policy name and
/// short enough that the paths built from it stay well inside `PATH_MAX`.
pub const max_policy_name_bytes: usize = 64;

/// Whether `name` is a policy name that can be used to build a path. A policy
/// name reaches a path and an argument vector, so it is checked as input
/// rather than trusted: letters, digits, `.`, `-` and `_`, never empty, never
/// starting with a dot, so it cannot be `.`, `..`, or anything that leaves the
/// directory it names.
pub fn validPolicyName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_policy_name_bytes) return false;
    if (name[0] == '.') return false;
    for (name) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// The file-contexts file of `policy`, written into `buffer`.
///
/// A caller-supplied buffer rather than an allocation because the guest agent
/// is libc-free and allocates as little as it can, and because the length is
/// bounded by `max_policy_name_bytes` either way.
pub fn fileContextsPath(buffer: []u8, policy: []const u8) error{ InvalidPolicy, NoSpaceLeft }![]const u8 {
    if (!validPolicyName(policy)) return error.InvalidPolicy;
    return std.fmt.bufPrint(buffer, "/etc/selinux/{s}/contexts/files/file_contexts", .{policy}) catch
        return error.NoSpaceLeft;
}

/// The policy `/etc/selinux/config` names, or nothing when it names none.
///
/// Parsed rather than assumed, and parsed from the target rather than from the
/// request, because the policy a relabel must use is whichever one the image
/// carries when the relabel runs -- which a package action in the same run can
/// have changed. Comments and blank lines are skipped; a `SELINUXTYPE` naming
/// something that is not a usable policy name is reported as absent, because a
/// name that cannot build a path is not a policy this can act on.
pub fn parseConfiguredPolicy(contents: []const u8) ?[]const u8 {
    const found = findSetting(contents, policy_setting) orelse return null;
    const value = contents[found.value_start..found.value_end];
    if (!validPolicyName(value)) return null;
    return value;
}

/// The SELinux mode a configuration asks the target's kernel to boot in.
///
/// Defined here, beside the parser, so the request type, the record and the
/// guest agent all name one enum rather than three that agree by accident.
pub const Mode = enum {
    enforcing,
    permissive,
    disabled,
};

/// The mode `/etc/selinux/config` names, or nothing when it names none.
///
/// Read for the record rather than for the run: a relabel is carried out the
/// same way whatever the mode says, but a relabel of a root whose own
/// configuration says `disabled` did work that will never take effect, and
/// nothing else a run publishes reveals that. Unrecognised values are reported
/// as absent -- a mode this cannot name is not one it should claim to.
pub fn parseConfiguredMode(contents: []const u8) ?Mode {
    const found = findSetting(contents, mode_setting) orelse return null;
    return std.meta.stringToEnum(Mode, contents[found.value_start..found.value_end]);
}

/// Where one setting's value sits in the file: the byte range the value
/// occupies, with the surrounding blanks and quotes left outside it so an
/// edit can replace the value without disturbing how it was written.
const Assignment = struct {
    value_start: usize,
    value_end: usize,
};

/// The last uncommented `key=` assignment in `contents`, or nothing when the
/// file declares none.
///
/// The *last* one, because that is the one the target itself honours:
/// libselinux reads this file to the end and lets a later assignment overwrite
/// an earlier one. Both parsers above and `renderConfig` below go through
/// here, so the setting a `.configure` edits is the setting a later read
/// reports -- a writer that edited the first assignment while the reader
/// reported the last would produce a file whose recorded before-state and
/// after-state described different lines.
fn findSetting(contents: []const u8, key: []const u8) ?Assignment {
    var found: ?Assignment = null;
    var offset: usize = 0;
    while (offset < contents.len) {
        const line_end = std.mem.indexOfScalarPos(u8, contents, offset, '\n') orelse contents.len;
        defer offset = line_end + 1;

        // The carriage return of a CRLF file belongs to the line ending rather
        // than to the value, and it must survive an edit either way.
        var body_end = line_end;
        if (body_end > offset and contents[body_end - 1] == '\r') body_end -= 1;

        var start = offset;
        while (start < body_end and (contents[start] == ' ' or contents[start] == '\t')) start += 1;
        if (start == body_end or contents[start] == '#') continue;

        const equals = std.mem.indexOfScalarPos(u8, contents[0..body_end], start, '=') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, contents[start..equals], " \t"), key)) continue;

        var value_start = equals + 1;
        var value_end = body_end;
        while (value_start < value_end and isBlank(contents[value_start])) value_start += 1;
        while (value_end > value_start and isBlank(contents[value_end - 1])) value_end -= 1;
        // A matching pair of quotes is part of how the file spells the value
        // rather than part of the value, so an edit puts the new one back
        // inside them. Stripped as a pair rather than as padding, so that an
        // empty `""` yields the position between the quotes instead of the
        // one after them.
        if (value_end - value_start >= 2 and
            contents[value_start] == '"' and contents[value_end - 1] == '"')
        {
            value_start += 1;
            value_end -= 1;
            while (value_start < value_end and isBlank(contents[value_start])) value_start += 1;
            while (value_end > value_start and isBlank(contents[value_end - 1])) value_end -= 1;
        }
        found = .{ .value_start = value_start, .value_end = value_end };
    }
    return found;
}

fn isBlank(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

pub const RenderError = error{
    /// The configuration declares no assignment of the setting the request
    /// asks to change. Planting one would mean guessing that the target reads
    /// a setting the target never mentioned, so it is refused by name --
    /// exactly as `grub_defaults` refuses a file that declares no
    /// `GRUB_CMDLINE_LINUX`.
    MissingSelinuxSetting,
    /// The requested policy is not a name that can build a path. Checked here
    /// as well as at validation because this is the last point before the name
    /// is written into a file the target will act on.
    InvalidPolicy,
    /// Neither a mode nor a policy was named, so there is nothing to render.
    /// The host refuses this shape at validation; repeated here so a caller
    /// on either side of the privilege boundary cannot obtain an unchanged
    /// file from a request that asked for a change.
    NoChangeRequested,
    NoSpaceLeft,
};

/// The bytes `/etc/selinux/config` should become, given what it currently
/// holds and what the request asks to change, written into `buffer`.
///
/// Rendering rather than writing, so this module keeps the filesystem-free
/// property declared at the top of the file: the host, the privileged worker
/// and the guest agent all produce the same bytes from the same inputs, and
/// only the executor touches a file. It is the same split `renderResolverBody`
/// uses for `/etc/resolv.conf`. A caller-supplied buffer rather than an
/// allocation because the guest agent is libc-free and allocates as little as
/// it can, exactly as `fileContextsPath` does; `buffer` must not alias
/// `existing`.
///
/// The edit is **surgical, never regenerative**, for the same reason
/// `grub_defaults.append` is: the value of the last uncommented assignment is
/// replaced and every other byte -- comments, blank lines, the distro's own
/// explanatory header, quoting, CRLF endings, a final line without a newline
/// -- survives unchanged. A configuration this rewrote wholesale would be one
/// whose format this claimed to understand completely, and the setting it
/// dropped would be found by whoever booted the image.
pub fn renderConfig(
    buffer: []u8,
    existing: []const u8,
    mode: ?Mode,
    policy: ?[]const u8,
) RenderError![]const u8 {
    if (mode == null and policy == null) return error.NoChangeRequested;
    if (policy) |name| {
        if (!validPolicyName(name)) return error.InvalidPolicy;
    }

    const Edit = struct { at: Assignment, text: []const u8 };
    var edits: [2]Edit = undefined;
    var count: usize = 0;
    if (mode) |value| {
        edits[count] = .{
            .at = findSetting(existing, mode_setting) orelse return error.MissingSelinuxSetting,
            .text = @tagName(value),
        };
        count += 1;
    }
    if (policy) |name| {
        edits[count] = .{
            .at = findSetting(existing, policy_setting) orelse return error.MissingSelinuxSetting,
            .text = name,
        };
        count += 1;
    }
    // Spliced in file order rather than in the order the request named them,
    // because the copy walks `existing` once.
    if (count == 2 and edits[1].at.value_start < edits[0].at.value_start) {
        std.mem.swap(Edit, &edits[0], &edits[1]);
    }

    var written: usize = 0;
    var copied: usize = 0;
    for (edits[0..count]) |edit| {
        written += try appendBytes(buffer, written, existing[copied..edit.at.value_start]);
        written += try appendBytes(buffer, written, edit.text);
        copied = edit.at.value_end;
    }
    written += try appendBytes(buffer, written, existing[copied..]);
    return buffer[0..written];
}

fn appendBytes(buffer: []u8, at: usize, bytes: []const u8) error{NoSpaceLeft}!usize {
    if (bytes.len > buffer.len - at) return error.NoSpaceLeft;
    @memcpy(buffer[at..][0..bytes.len], bytes);
    return bytes.len;
}

/// Whether a run relabels the root as part of changing the SELinux
/// configuration.
///
/// A caller choice, because only the caller knows whether the tree it is
/// handing over is already labelled -- but not a caller choice with an unsafe
/// default. `when_needed` is the default and the reason this is not a `bool`:
/// raising a root from `disabled` to `enforcing` without relabelling produces
/// an image that does not boot, which is precisely the failure a relabel
/// exists to prevent.
pub const RelabelPolicy = enum {
    /// Relabel when this run makes the existing labels wrong: when it raises
    /// the mode away from `disabled`, or when it switches to a different
    /// policy, whose `file_contexts` assigns different labels to the same
    /// paths.
    when_needed,
    /// Relabel whatever the target was configured with.
    always,
    /// Do not relabel. For a caller who knows the tree is already labelled
    /// under the policy this leaves in place and does not want to spend the
    /// walk -- and, unlike a `false`, one who said so on purpose.
    never,
};

/// Why a run did or did not relabel, decided while it executes.
pub const RelabelReason = enum {
    /// `always`: the request asked for it outright.
    requested,
    /// `when_needed`, and this run took the target off `disabled` -- or off a
    /// mode its configuration did not name in terms this recognises, which is
    /// treated the same way because a root that cannot be shown to be labelled
    /// is one that must be.
    mode_raised,
    /// `when_needed`, and this run switched the target to a different policy,
    /// whose file contexts the existing labels were not assigned from.
    policy_changed,
    /// `when_needed`, and nothing this run did invalidated the existing
    /// labels.
    not_needed,
    /// `never`: the caller declined, including where the run raised the mode.
    declined,
};

/// Whether the labels the target carries survive the change this run makes.
///
/// Decided here, from values both executors read out of the target, so the
/// privileged worker and the guest agent reach the same answer rather than two
/// answers that agree until one of them is edited. It cannot be decided while
/// the plan is resolved, because `previous_mode` and `previous_policy` are
/// properties of the target read while the run executes -- a package action in
/// the same run can replace either.
///
/// `requested_mode` and `requested_policy` are what the request asked to
/// write, each absent when the request leaves that setting alone.
pub fn relabelReason(
    policy: RelabelPolicy,
    previous_mode: ?Mode,
    previous_policy: []const u8,
    requested_mode: ?Mode,
    requested_policy: ?[]const u8,
) RelabelReason {
    switch (policy) {
        .never => return .declined,
        .always => return .requested,
        .when_needed => {},
    }
    if (requested_mode) |mode| {
        // An unrecognised or absent `SELINUX=` is treated as `disabled`: it is
        // the answer that relabels, and spending the walk is the recoverable
        // outcome where not spending it is an image that does not boot.
        const was_off = previous_mode == null or previous_mode.? == .disabled;
        if (was_off and mode != .disabled) return .mode_raised;
    }
    if (requested_policy) |name| {
        if (!std.mem.eql(u8, name, previous_policy)) return .policy_changed;
    }
    return .not_needed;
}

pub fn relabels(reason: RelabelReason) bool {
    return switch (reason) {
        .requested, .mode_raised, .policy_changed => true,
        .not_needed, .declined => false,
    };
}

/// The kernel parameter that switches SELinux off whatever the target's
/// `/etc/selinux/config` says. The kernel treats `selinux=0` as off and
/// anything else as on, so this is the whole spelling rather than a prefix.
pub const disabling_kernel_option = "selinux=0";

/// Whether `contents` -- a bootloader configuration or a BLS entry file --
/// carries `selinux=0` on a command line.
///
/// Read rather than edited. A root whose command line disables SELinux boots
/// with it off however this run configured it, so a `.configure` on such an
/// image has done nothing observable, and nothing else a run publishes reveals
/// that. Editing the command line is a different request with its own model
/// (`boot_security.extra_kernel_options`), and doing it silently here would
/// change what the image boots with on the strength of an inference.
///
/// A whole-file scan bounded by word boundaries, rather than a parse: these
/// files have several formats between them and the question is only whether
/// the token is present, which every format spells the same way.
pub fn carriesDisablingKernelOption(contents: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, contents, offset, disabling_kernel_option)) |found| {
        defer offset = found + 1;
        if (found != 0 and !isCommandLineSeparator(contents[found - 1])) continue;
        const after = found + disabling_kernel_option.len;
        if (after != contents.len and !isCommandLineSeparator(contents[after])) continue;
        return true;
    }
    return false;
}

fn isCommandLineSeparator(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n', '"', '\'' => true,
        else => false,
    };
}

test "parses the configured mode" {
    try std.testing.expectEqual(
        Mode.enforcing,
        parseConfiguredMode("# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n").?,
    );
    try std.testing.expectEqual(
        Mode.permissive,
        parseConfiguredMode("  SELINUX = \"permissive\"  \r\n").?,
    );
    try std.testing.expectEqual(
        Mode.disabled,
        parseConfiguredMode("SELINUX=disabled\n").?,
    );
    // `SELINUXTYPE` starts with the same eight bytes and is a different
    // setting; a prefix match here would report a policy name as a mode.
    try std.testing.expect(parseConfiguredMode("SELINUXTYPE=targeted\n") == null);
    try std.testing.expect(parseConfiguredMode("#SELINUX=enforcing\n") == null);
    try std.testing.expect(parseConfiguredMode("SELINUX=whatever\n") == null);
    // The target's own loader reads to the end and lets a later assignment
    // overwrite an earlier one, so this reports the line the target obeys.
    try std.testing.expectEqual(
        Mode.permissive,
        parseConfiguredMode("SELINUX=enforcing\nSELINUX=permissive\n").?,
    );
}

test "parses the configured policy" {
    try std.testing.expectEqualStrings("targeted", parseConfiguredPolicy(
        "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
    ).?);
    try std.testing.expectEqualStrings("mls", parseConfiguredPolicy(
        "  SELINUXTYPE = \"mls\"  \r\n",
    ).?);
    try std.testing.expect(parseConfiguredPolicy("SELINUX=enforcing\n") == null);
    try std.testing.expect(parseConfiguredPolicy("SELINUXTYPE=../escape\n") == null);
    try std.testing.expect(parseConfiguredPolicy("#SELINUXTYPE=targeted\n") == null);
    try std.testing.expectEqualStrings("mls", parseConfiguredPolicy(
        "SELINUXTYPE=targeted\nSELINUXTYPE=mls\n",
    ).?);
}

test "rejects policy names that cannot build a path" {
    try std.testing.expect(validPolicyName("targeted"));
    try std.testing.expect(!validPolicyName(""));
    try std.testing.expect(!validPolicyName("."));
    try std.testing.expect(!validPolicyName(".."));
    try std.testing.expect(!validPolicyName("a/b"));
    try std.testing.expect(!validPolicyName("a b"));
    try std.testing.expect(!validPolicyName("a" ** (max_policy_name_bytes + 1)));
}

test "builds the file contexts path" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/etc/selinux/targeted/contexts/files/file_contexts",
        try fileContextsPath(&buffer, "targeted"),
    );
    try std.testing.expectError(error.InvalidPolicy, fileContextsPath(&buffer, "../x"));
}

/// The header a Red Hat family image ships this file with, kept verbatim
/// because every test below is about what survives an edit.
const test_config =
    "# This file controls the state of SELinux on the system.\n" ++
    "# SELINUX= can take one of these three values:\n" ++
    "#     enforcing - SELinux security policy is enforced.\n" ++
    "SELINUX=enforcing\n" ++
    "# SELINUXTYPE= can take one of these values:\n" ++
    "SELINUXTYPE=targeted\n";

test "renders a mode change and leaves every other byte alone" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectEqualStrings(
        "# This file controls the state of SELinux on the system.\n" ++
            "# SELINUX= can take one of these three values:\n" ++
            "#     enforcing - SELinux security policy is enforced.\n" ++
            "SELINUX=permissive\n" ++
            "# SELINUXTYPE= can take one of these values:\n" ++
            "SELINUXTYPE=targeted\n",
        try renderConfig(&buffer, test_config, .permissive, null),
    );
}

test "renders a policy change without touching the mode" {
    var buffer: [1024]u8 = undefined;
    const rendered = try renderConfig(&buffer, test_config, null, "mls");
    try std.testing.expectEqualStrings("mls", parseConfiguredPolicy(rendered).?);
    try std.testing.expectEqual(Mode.enforcing, parseConfiguredMode(rendered).?);
}

test "renders both settings in one pass" {
    var buffer: [1024]u8 = undefined;
    const rendered = try renderConfig(&buffer, test_config, .enforcing, "mls");
    try std.testing.expectEqualStrings(
        "# This file controls the state of SELinux on the system.\n" ++
            "# SELINUX= can take one of these three values:\n" ++
            "#     enforcing - SELinux security policy is enforced.\n" ++
            "SELINUX=enforcing\n" ++
            "# SELINUXTYPE= can take one of these values:\n" ++
            "SELINUXTYPE=mls\n",
        rendered,
    );
    // The rendered bytes are what a later read reports, or the record would
    // describe a file the target does not have.
    try std.testing.expectEqual(Mode.enforcing, parseConfiguredMode(rendered).?);
    try std.testing.expectEqualStrings("mls", parseConfiguredPolicy(rendered).?);
}

test "the policy setting is edited even when it precedes the mode" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectEqualStrings(
        "SELINUXTYPE=mls\nSELINUX=permissive\n",
        try renderConfig(&buffer, "SELINUXTYPE=targeted\nSELINUX=enforcing\n", .permissive, "mls"),
    );
}

test "quoting, indentation, CRLF and a missing final newline all survive" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectEqualStrings(
        "  SELINUX = \"disabled\"  \r\n\tSELINUXTYPE\t=\tminimum",
        try renderConfig(
            &buffer,
            "  SELINUX = \"enforcing\"  \r\n\tSELINUXTYPE\t=\ttargeted",
            .disabled,
            "minimum",
        ),
    );
}

test "the last uncommented assignment is the one edited" {
    var buffer: [1024]u8 = undefined;
    // The target's own loader reads to the end of the file and lets the later
    // assignment win, so editing the earlier one would leave the run's change
    // overwritten by a line it did not touch.
    const existing = "SELINUX=disabled\n#SELINUX=permissive\nSELINUX=permissive\n";
    const rendered = try renderConfig(&buffer, existing, .enforcing, null);
    try std.testing.expectEqualStrings(
        "SELINUX=disabled\n#SELINUX=permissive\nSELINUX=enforcing\n",
        rendered,
    );
    try std.testing.expectEqual(Mode.enforcing, parseConfiguredMode(rendered).?);
}

test "an empty value is filled in rather than refused" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectEqualStrings(
        "SELINUX=enforcing\nSELINUXTYPE=\"targeted\"\n",
        try renderConfig(&buffer, "SELINUX=\nSELINUXTYPE=\"\"\n", .enforcing, "targeted"),
    );
}

test "a setting the file does not declare is refused rather than planted" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectError(error.MissingSelinuxSetting, renderConfig(
        &buffer,
        "SELINUXTYPE=targeted\n",
        .enforcing,
        null,
    ));
    try std.testing.expectError(error.MissingSelinuxSetting, renderConfig(
        &buffer,
        "SELINUX=enforcing\n",
        null,
        "targeted",
    ));
    // A commented-out declaration is not a declaration.
    try std.testing.expectError(error.MissingSelinuxSetting, renderConfig(
        &buffer,
        "# SELINUX=enforcing\n",
        .permissive,
        null,
    ));
}

test "a render that would change nothing, and one that could not build a path, are refused" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectError(
        error.NoChangeRequested,
        renderConfig(&buffer, test_config, null, null),
    );
    try std.testing.expectError(
        error.InvalidPolicy,
        renderConfig(&buffer, test_config, null, "../escape"),
    );
}

test "a buffer too small for the result is refused rather than truncated" {
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(
        error.NoSpaceLeft,
        renderConfig(&buffer, test_config, .permissive, null),
    );
}

test "the relabel decision follows what the run changes" {
    const cases = [_]struct {
        why: []const u8,
        policy: RelabelPolicy,
        previous_mode: ?Mode,
        previous_policy: []const u8,
        requested_mode: ?Mode,
        requested_policy: ?[]const u8,
        expected: RelabelReason,
    }{
        .{
            .why = "a root taken off disabled carries no labels the new mode can enforce",
            .policy = .when_needed,
            .previous_mode = .disabled,
            .previous_policy = "targeted",
            .requested_mode = .enforcing,
            .requested_policy = null,
            .expected = .mode_raised,
        },
        .{
            .why = "a root that cannot be shown to have been enabled is treated as disabled",
            .policy = .when_needed,
            .previous_mode = null,
            .previous_policy = "targeted",
            .requested_mode = .permissive,
            .requested_policy = null,
            .expected = .mode_raised,
        },
        .{
            .why = "a permissive root is already labelled, so raising it needs no walk",
            .policy = .when_needed,
            .previous_mode = .permissive,
            .previous_policy = "targeted",
            .requested_mode = .enforcing,
            .requested_policy = null,
            .expected = .not_needed,
        },
        .{
            .why = "a different policy assigns different labels to the same paths",
            .policy = .when_needed,
            .previous_mode = .enforcing,
            .previous_policy = "targeted",
            .requested_mode = null,
            .requested_policy = "mls",
            .expected = .policy_changed,
        },
        .{
            .why = "rewriting the policy with the name it already had changes no label",
            .policy = .when_needed,
            .previous_mode = .enforcing,
            .previous_policy = "targeted",
            .requested_mode = null,
            .requested_policy = "targeted",
            .expected = .not_needed,
        },
        .{
            .why = "turning enforcement off leaves the labels as correct as they were",
            .policy = .when_needed,
            .previous_mode = .enforcing,
            .previous_policy = "targeted",
            .requested_mode = .disabled,
            .requested_policy = null,
            .expected = .not_needed,
        },
        .{
            .why = "an outright request needs no justification from the target",
            .policy = .always,
            .previous_mode = .enforcing,
            .previous_policy = "targeted",
            .requested_mode = .enforcing,
            .requested_policy = null,
            .expected = .requested,
        },
        .{
            .why = "a caller who declined is obeyed, and the record says they declined",
            .policy = .never,
            .previous_mode = .disabled,
            .previous_policy = "targeted",
            .requested_mode = .enforcing,
            .requested_policy = null,
            .expected = .declined,
        },
    };
    for (cases) |case| {
        const reason = relabelReason(
            case.policy,
            case.previous_mode,
            case.previous_policy,
            case.requested_mode,
            case.requested_policy,
        );
        std.testing.expectEqual(case.expected, reason) catch |err| {
            std.debug.print("{s}\n", .{case.why});
            return err;
        };
    }
    try std.testing.expect(relabels(.mode_raised));
    try std.testing.expect(relabels(.policy_changed));
    try std.testing.expect(relabels(.requested));
    try std.testing.expect(!relabels(.not_needed));
    try std.testing.expect(!relabels(.declined));
}

test "a command line that switches SELinux off is recognised on a word boundary" {
    try std.testing.expect(carriesDisablingKernelOption(
        "linux /vmlinuz root=UUID=1 selinux=0 quiet\n",
    ));
    try std.testing.expect(carriesDisablingKernelOption("options selinux=0"));
    try std.testing.expect(carriesDisablingKernelOption(
        "GRUB_CMDLINE_LINUX=\"selinux=0\"\n",
    ));
    // `selinux=1` is the kernel's own spelling of leaving it on, and
    // `enforcing=0` only asks for permissive rather than off.
    try std.testing.expect(!carriesDisablingKernelOption("linux /vmlinuz selinux=1\n"));
    try std.testing.expect(!carriesDisablingKernelOption("linux /vmlinuz enforcing=0\n"));
    try std.testing.expect(!carriesDisablingKernelOption("linux /vmlinuz noselinux=0\n"));
    try std.testing.expect(!carriesDisablingKernelOption("linux /vmlinuz selinux=00\n"));
    try std.testing.expect(!carriesDisablingKernelOption(""));
}
