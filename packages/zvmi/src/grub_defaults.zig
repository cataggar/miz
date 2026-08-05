//! Adding kernel command-line options to `/etc/default/grub`, the source of
//! truth a distro's own bootloader generator reads.
//!
//! `boot_options` edits the generated boot entries directly, which is the
//! right answer for an image whose command line is only ever written by zvmi.
//! A distro-installed image is different: its `grub.cfg` is *output*.
//! `grub2-mkconfig` regenerates it from `/etc/default/grub`, the scripts in
//! `/etc/grub.d/`, and whatever kernels are installed, and it does so
//! whenever a kernel package is installed or removed. An option appended to
//! the generated file there survives exactly until the next kernel update.
//! Editing the input and re-running the generator is what makes the change
//! durable, and it is the reason this path needs a chroot at all.
//!
//! This module is the input half, and only the text transformation, so the
//! part that decides what an image's command line says can be tested without
//! root, a loop device, or a distro fixture.
//!
//! * **`GRUB_CMDLINE_LINUX`, not `GRUB_CMDLINE_LINUX_DEFAULT`.** The first
//!   reaches every generated entry including the recovery ones; the second
//!   reaches only the default entry. `boot_options` already promises every
//!   entry or none, and an option that vanishes when a machine boots its
//!   fallback entry is the kind of difference nobody finds until they need
//!   the fallback entry.
//! * **Surgical, never regenerative.** The assignment is spliced in place.
//!   Everything else in the file -- comments, blank lines, the distro's other
//!   variables, CRLF endings, a last line without a newline -- survives byte
//!   for byte, for the same reason `identity_rewrite` splices `/etc/fstab`
//!   rather than re-emitting it.
//! * **A file that does not declare the variable is refused, not amended.**
//!   Writing a `GRUB_CMDLINE_LINUX` line into a file that never had one means
//!   guessing that the distro reads it, and a guess that is wrong produces an
//!   image that silently boots without the argument it was asked to boot
//!   with. The caller gets a named error and can say so.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// The variable this module edits. Named here because the error messages and
/// the documentation both have to say it, and because a caller verifying the
/// result has to look for the same one.
pub const command_line_variable = "GRUB_CMDLINE_LINUX";

/// Upper bound on an `/etc/default/grub` the caller will read into memory.
/// The file is a handful of shell assignments a human maintains; anything
/// past this is not one.
pub const max_file_bytes: usize = 256 * 1024;

pub const Error = error{
    /// The file declares no `GRUB_CMDLINE_LINUX` assignment outside a
    /// comment. Amending it would mean guessing that the target's generator
    /// reads a variable the target never mentioned.
    MissingCommandLineVariable,
    /// The assignment's value opens a quote that no later character closes.
    /// The file is not valid shell, so no edit to it has a defined meaning.
    UnterminatedQuotedValue,
    /// The assignment already has a value and does not quote it. Appending
    /// there would put the option text outside every quote, where `;`, `&`,
    /// `|`, `>` and a bare space are all live shell syntax rather than parts
    /// of a command line -- the injection `validateOptions` exists to
    /// prevent, reintroduced by the surrounding file. The unquoted set is
    /// open-ended, so this is refused rather than filtered, and adding the
    /// quotes on the operator's behalf is refused too: `a\ b` means one thing
    /// bare and another inside quotes.
    UnquotedCommandLineValue,
    /// The option text carries a character that means something to the shell
    /// inside a quoted assignment. See `validateOptions`.
    UnsupportedShellCharacter,
};

pub const AppendError = Error || Allocator.Error;

/// Whether `options` can be spliced into a shell assignment.
///
/// This is a stricter rule than `boot_options.validateOptions`, and the
/// difference is the point: a boot entry file is read by the bootloader,
/// while `/etc/default/grub` is **sourced by the shell** that runs
/// `grub-mkconfig` as root inside the target. A quote would close the
/// assignment, and a `$` or a backtick would substitute rather than appear.
/// Neither can be escaped into safety across both quoting styles, and a
/// kernel command line has no use for either, so they are refused by name
/// rather than quoted, stripped or hoped over.
///
/// The rule is only sound because `append` writes into a **quoted** value and
/// refuses an unquoted one; outside quotes the dangerous set is open-ended
/// and no list of bytes would be enough.
pub fn validateOptions(options: []const u8) Error!void {
    for (options) |byte| switch (byte) {
        '"', '\'', '`', '$', '\\' => return error.UnsupportedShellCharacter,
        else => {},
    };
}

pub const Outcome = struct {
    /// The rewritten file, or null when the assignment already ended with
    /// exactly these options and nothing had to change. Owned by the caller's
    /// allocator when present.
    text: ?[]u8 = null,
    /// Whether the declared options were already the end of the value. A
    /// re-run of the same request over an image it already produced reports
    /// this rather than appending a second copy.
    already_current: bool = false,
};

/// Appends `options` to the value of the last `GRUB_CMDLINE_LINUX` assignment
/// in `contents`, preserving every other byte.
///
/// The *last* assignment wins because the file is shell: a later assignment
/// overwrites an earlier one, so appending to any but the last would edit a
/// value the generator never sees.
pub fn append(
    allocator: Allocator,
    contents: []const u8,
    options: []const u8,
) AppendError!Outcome {
    const target = try findLastAssignment(contents) orelse
        return error.MissingCommandLineVariable;

    if (valueCarriesSuffix(contents[target.value_start..target.value_end], options)) {
        return .{ .already_current = true };
    }

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    out.writer.writeAll(contents[0..target.value_end]) catch return error.OutOfMemory;
    // `GRUB_CMDLINE_LINUX=` with no value is completed into a quoted one:
    // the options must not end up as bare shell words, and there is no
    // existing text for the quotes to change the meaning of.
    if (target.quote == null) out.writer.writeByte('"') catch return error.OutOfMemory;
    // A value that is empty gets the options alone: a leading space inside
    // the quotes would be a command line starting with whitespace, which is
    // harmless but is not what the file would have looked like had a human
    // written it.
    if (target.value_end > target.value_start) {
        out.writer.writeByte(' ') catch return error.OutOfMemory;
    }
    out.writer.writeAll(options) catch return error.OutOfMemory;
    if (target.quote == null) out.writer.writeByte('"') catch return error.OutOfMemory;
    out.writer.writeAll(contents[target.value_end..]) catch return error.OutOfMemory;
    return .{ .text = try out.toOwnedSlice() };
}

/// Whether the last `GRUB_CMDLINE_LINUX` assignment's value ends with
/// `options` as a whole word. The verification pass over a file this module
/// wrote, and the check a caller makes before deciding a target needs no
/// edit at all.
pub fn carries(contents: []const u8, options: []const u8) Error!bool {
    const target = try findLastAssignment(contents) orelse
        return error.MissingCommandLineVariable;
    return valueCarriesSuffix(contents[target.value_start..target.value_end], options);
}

const Assignment = struct {
    /// First byte of the value, inside any opening quote.
    value_start: usize,
    /// One past the last byte of the value, inside any closing quote.
    value_end: usize,
    /// The quote enclosing the value, or null for `GRUB_CMDLINE_LINUX=` with
    /// no value at all -- the one unquoted spelling that can be edited
    /// safely, because there is no existing text whose meaning quoting it
    /// could change.
    quote: ?u8,
};

/// Finds the last uncommented `GRUB_CMDLINE_LINUX=` assignment and locates
/// its value. Returns null when the file declares none, and an error only
/// when a declaration it did find cannot be read.
fn findLastAssignment(contents: []const u8) Error!?Assignment {
    var found: ?Assignment = null;
    var offset: usize = 0;
    while (offset < contents.len) {
        const line_end = std.mem.indexOfScalarPos(u8, contents, offset, '\n') orelse contents.len;
        defer offset = line_end + 1;

        const raw = contents[offset..line_end];
        const body = if (raw.len != 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        const lead = leadingBlankCount(body);
        const statement = body[lead..];
        // `export GRUB_CMDLINE_LINUX=...` is the same assignment with a
        // keyword in front, and a distro that writes it that way means the
        // same thing by it.
        const named = stripExport(statement);
        if (!std.mem.startsWith(u8, named, command_line_variable ++ "=")) continue;

        const value_offset = offset + lead + (statement.len - named.len) +
            command_line_variable.len + 1;
        found = try locateValue(contents, value_offset, offset + lead + body.len - lead);
    }
    return found;
}

/// Where a value begins and ends, given the byte just past the `=`.
///
/// Double and single quoted values are edited; a value that is present and
/// unquoted is refused, because appending to it would place the options
/// outside every quote.
fn locateValue(contents: []const u8, value_offset: usize, line_end: usize) Error!Assignment {
    if (value_offset >= line_end) {
        return .{ .value_start = value_offset, .value_end = value_offset, .quote = null };
    }
    const opener = contents[value_offset];
    if (opener != '"' and opener != '\'') return error.UnquotedCommandLineValue;
    const start = value_offset + 1;
    var index = start;
    while (index < line_end) : (index += 1) {
        // A backslash escapes the next byte inside double quotes, so a
        // `\"` is part of the value rather than its end.
        if (opener == '"' and contents[index] == '\\' and index + 1 < line_end) {
            index += 1;
            continue;
        }
        if (contents[index] == opener) {
            return .{ .value_start = start, .value_end = index, .quote = opener };
        }
    }
    return error.UnterminatedQuotedValue;
}

/// Whether `value` ends with `options` on a word boundary. A value ending in
/// `quiet` does not carry `iet`, and one ending in `console=ttyS0` does not
/// carry `ttyS0`.
fn valueCarriesSuffix(value: []const u8, options: []const u8) bool {
    const trimmed = std.mem.trimEnd(u8, value, " \t");
    if (!std.mem.endsWith(u8, trimmed, options)) return false;
    if (trimmed.len == options.len) return true;
    const preceding = trimmed[trimmed.len - options.len - 1];
    return preceding == ' ' or preceding == '\t';
}

fn leadingBlankCount(line: []const u8) usize {
    var index: usize = 0;
    while (index < line.len and (line[index] == ' ' or line[index] == '\t')) index += 1;
    return index;
}

fn stripExport(statement: []const u8) []const u8 {
    const keyword = "export ";
    if (!std.mem.startsWith(u8, statement, keyword)) return statement;
    const rest = statement[keyword.len..];
    return rest[leadingBlankCount(rest)..];
}

const test_defaults =
    "# generated by anaconda\n" ++
    "GRUB_TIMEOUT=5\n" ++
    "GRUB_DISTRIBUTOR=\"$(sed 's, release .*$,,g' /etc/system-release)\"\n" ++
    "GRUB_DEFAULT=saved\n" ++
    "GRUB_CMDLINE_LINUX=\"root=UUID=1111 rd.lvm.lv=vg/root crashkernel=auto\"\n" ++
    "GRUB_DISABLE_RECOVERY=\"true\"\n";

test "the options land inside the quoted value and nothing else moves" {
    const outcome = try append(std.testing.allocator, test_defaults, "console=ttyS0 quiet");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expect(!outcome.already_current);
    try std.testing.expectEqualStrings(
        "# generated by anaconda\n" ++
            "GRUB_TIMEOUT=5\n" ++
            "GRUB_DISTRIBUTOR=\"$(sed 's, release .*$,,g' /etc/system-release)\"\n" ++
            "GRUB_DEFAULT=saved\n" ++
            "GRUB_CMDLINE_LINUX=\"root=UUID=1111 rd.lvm.lv=vg/root crashkernel=auto console=ttyS0 quiet\"\n" ++
            "GRUB_DISABLE_RECOVERY=\"true\"\n",
        outcome.text.?,
    );
}

test "a file that already carries the options is left exactly as it was" {
    const outcome = try append(std.testing.allocator, test_defaults, "crashkernel=auto");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expect(outcome.already_current);
    try std.testing.expectEqual(@as(?[]u8, null), outcome.text);
    try std.testing.expect(try carries(test_defaults, "crashkernel=auto"));
}

test "an option that is only the tail of an existing word is not already current" {
    // `crashkernel=auto` ends the value, so a naive suffix test would call
    // `auto` present and publish an image without it.
    try std.testing.expect(!try carries(test_defaults, "auto"));
    const outcome = try append(std.testing.allocator, test_defaults, "auto");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expect(!outcome.already_current);
    try std.testing.expect(std.mem.indexOf(u8, outcome.text.?, "crashkernel=auto auto\"") != null);
}

test "the last assignment is the one that is edited" {
    const contents =
        "GRUB_CMDLINE_LINUX=\"first\"\n" ++
        "# a comment mentioning GRUB_CMDLINE_LINUX= does not count\n" ++
        "GRUB_CMDLINE_LINUX=\"second\"\n";
    const outcome = try append(std.testing.allocator, contents, "third");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "GRUB_CMDLINE_LINUX=\"first\"\n" ++
            "# a comment mentioning GRUB_CMDLINE_LINUX= does not count\n" ++
            "GRUB_CMDLINE_LINUX=\"second third\"\n",
        outcome.text.?,
    );
}

test "an empty value takes the options without a leading space" {
    const contents = "GRUB_CMDLINE_LINUX=\"\"\n";
    const outcome = try append(std.testing.allocator, contents, "console=ttyS0");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("GRUB_CMDLINE_LINUX=\"console=ttyS0\"\n", outcome.text.?);
}

test "single quotes, an export keyword and leading blanks are all understood" {
    const contents = "  export GRUB_CMDLINE_LINUX='root=UUID=2222'\n";
    const outcome = try append(std.testing.allocator, contents, "quiet");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "  export GRUB_CMDLINE_LINUX='root=UUID=2222 quiet'\n",
        outcome.text.?,
    );
}

test "an unquoted value is refused rather than appended to outside the quotes" {
    // Appending here would emit `GRUB_CMDLINE_LINUX=quiet console=ttyS0`,
    // which assigns only `quiet` and runs `console=ttyS0` as a command --
    // and with option text carrying `;` or `&`, which `validateOptions`
    // permits because they are inert inside quotes, it would run whatever
    // the caller wrote, as root, inside the target.
    const contents = "GRUB_CMDLINE_LINUX=quiet\nGRUB_TIMEOUT=5\n";
    try std.testing.expectError(
        error.UnquotedCommandLineValue,
        append(std.testing.allocator, contents, "console=ttyS0"),
    );
    try std.testing.expectError(
        error.UnquotedCommandLineValue,
        carries(contents, "console=ttyS0"),
    );
}

test "an assignment with no value at all is completed into a quoted one" {
    const contents = "GRUB_CMDLINE_LINUX=\nGRUB_TIMEOUT=5\n";
    const outcome = try append(std.testing.allocator, contents, "console=ttyS0 quiet");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "GRUB_CMDLINE_LINUX=\"console=ttyS0 quiet\"\nGRUB_TIMEOUT=5\n",
        outcome.text.?,
    );
    // Nothing was there to quote differently, so the result means what the
    // options say and not something the shell rewrote.
    try std.testing.expect(try carries(outcome.text.?, "console=ttyS0 quiet"));
}

test "CRLF endings and a last line without a newline survive" {
    const contents = "GRUB_TIMEOUT=5\r\nGRUB_CMDLINE_LINUX=\"quiet\"\r\nGRUB_DEFAULT=saved";
    const outcome = try append(std.testing.allocator, contents, "console=ttyS0");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "GRUB_TIMEOUT=5\r\nGRUB_CMDLINE_LINUX=\"quiet console=ttyS0\"\r\nGRUB_DEFAULT=saved",
        outcome.text.?,
    );
}

test "a file declaring no command line variable is refused rather than amended" {
    const contents = "GRUB_TIMEOUT=5\n# GRUB_CMDLINE_LINUX=\"commented out\"\n";
    try std.testing.expectError(
        error.MissingCommandLineVariable,
        append(std.testing.allocator, contents, "quiet"),
    );
    try std.testing.expectError(error.MissingCommandLineVariable, carries(contents, "quiet"));
}

test "an unterminated quote is refused rather than guessed at" {
    const contents = "GRUB_CMDLINE_LINUX=\"quiet\n";
    try std.testing.expectError(
        error.UnterminatedQuotedValue,
        append(std.testing.allocator, contents, "console=ttyS0"),
    );
}

test "an escaped quote inside the value is part of the value" {
    const contents = "GRUB_CMDLINE_LINUX=\"a=\\\"b\\\" quiet\"\n";
    const outcome = try append(std.testing.allocator, contents, "console=ttyS0");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "GRUB_CMDLINE_LINUX=\"a=\\\"b\\\" quiet console=ttyS0\"\n",
        outcome.text.?,
    );
}

test "option text the shell would interpret is refused" {
    // `/etc/default/grub` is sourced, so these are not merely awkward: a
    // quote ends the assignment and the rest of the text becomes a command
    // the generator runs as root.
    for ([_][]const u8{
        "console=ttyS0\" ; touch /tmp/pwned ; x=\"",
        "console=ttyS0 $(id)",
        "console=ttyS0 `id`",
        "console=ttyS0 'quoted'",
        "console=ttyS0 back\\slash",
    }) |options| {
        try std.testing.expectError(
            error.UnsupportedShellCharacter,
            validateOptions(options),
        );
    }
    try validateOptions("console=ttyS0,115200n8 quiet systemd.unified_cgroup_hierarchy=0");
}

test "a name that merely starts with the variable is not the variable" {
    const contents =
        "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n" ++
        "GRUB_CMDLINE_LINUX=\"root=UUID=3333\"\n";
    const outcome = try append(std.testing.allocator, contents, "console=ttyS0");
    defer if (outcome.text) |text| std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(
        "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n" ++
            "GRUB_CMDLINE_LINUX=\"root=UUID=3333 console=ttyS0\"\n",
        outcome.text.?,
    );
}
