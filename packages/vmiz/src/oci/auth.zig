//! Registry authentication primitives.
//!
//! This module deliberately does not perform HTTP requests.  The registry
//! transport owns connections and redirect policy; authentication provides
//! bounded parsing, credential discovery, token request construction, and
//! token lifetime tracking.
const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const max_auth_file_size = 1024 * 1024;
pub const max_helper_output_size = 64 * 1024;
pub const max_token_response_size = 1024 * 1024;
pub const max_token_length = 16 * 1024;
pub const max_challenges = 64;
pub const max_challenge_parameters = 64;
pub const default_token_ttl_seconds: u64 = 60;
pub const max_token_ttl_seconds: u64 = 24 * 60 * 60;

pub const Error = error{
    MalformedChallenge,
    TooManyChallenges,
    MissingBearerRealm,
    InvalidTokenRealm,
    InvalidTokenResponse,
    TokenResponseTooLarge,
    AuthFileNotFound,
    InvalidAuthFile,
    CredentialHelperFailed,
    CredentialHelperOutputTooLarge,
    InvalidCredentialHelperOutput,
    InvalidCredentialHelperName,
    InvalidCredential,
} || Allocator.Error || std.Io.Writer.Error;

pub const Parameter = struct {
    name: []u8,
    value: []u8,

    fn deinit(self: *Parameter, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        self.* = undefined;
    }
};

/// An owned RFC 9110 authentication challenge.  `token68` is retained for
/// schemes that use it instead of auth-parameters.
pub const Challenge = struct {
    scheme: []u8,
    token68: ?[]u8,
    parameters: []Parameter,

    pub fn deinit(self: *Challenge, allocator: Allocator) void {
        allocator.free(self.scheme);
        if (self.token68) |value| allocator.free(value);
        for (self.parameters) |*item| item.deinit(allocator);
        allocator.free(self.parameters);
        self.* = undefined;
    }

    pub fn parameter(self: Challenge, name: []const u8) ?[]const u8 {
        for (self.parameters) |item| {
            if (std.ascii.eqlIgnoreCase(item.name, name)) return item.value;
        }
        return null;
    }

    pub fn isScheme(self: Challenge, name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.scheme, name);
    }
};

pub const ChallengeSet = struct {
    allocator: Allocator,
    challenges: []Challenge,

    pub fn deinit(self: *ChallengeSet) void {
        for (self.challenges) |*challenge| challenge.deinit(self.allocator);
        self.allocator.free(self.challenges);
        self.* = undefined;
    }

    pub fn first(self: ChallengeSet, scheme: []const u8) ?Challenge {
        for (self.challenges) |challenge| {
            if (challenge.isScheme(scheme)) return challenge;
        }
        return null;
    }
};

/// Parses every value of a WWW-Authenticate field, including repeated header
/// fields.  The grammar distinguishes auth-parameter commas from challenge
/// commas by checking whether the following token is followed by `=`.
pub fn parseChallenges(allocator: Allocator, values: []const []const u8) Error!ChallengeSet {
    var challenges = std.array_list.Managed(Challenge).init(allocator);
    errdefer {
        for (challenges.items) |*challenge| challenge.deinit(allocator);
        challenges.deinit();
    }

    for (values) |value| {
        var parser = ChallengeParser{ .input = value };
        while (true) {
            parser.skipListWhitespace();
            if (parser.done()) break;
            if (challenges.items.len >= max_challenges) return error.TooManyChallenges;
            try challenges.append(try parser.parseOne(allocator));
        }
    }

    return .{
        .allocator = allocator,
        .challenges = try challenges.toOwnedSlice(),
    };
}

/// Alias kept intentionally short for callers that already have extracted
/// WWW-Authenticate header values.
pub const parseWwwAuthenticate = parseChallenges;

const ChallengeParser = struct {
    input: []const u8,
    index: usize = 0,

    fn done(self: ChallengeParser) bool {
        return self.index == self.input.len;
    }

    fn skipWhitespace(self: *ChallengeParser) bool {
        const start = self.index;
        while (self.index < self.input.len and isOws(self.input[self.index])) : (self.index += 1) {}
        return self.index != start;
    }

    fn skipListWhitespace(self: *ChallengeParser) void {
        while (true) {
            _ = self.skipWhitespace();
            if (self.index == self.input.len or self.input[self.index] != ',') return;
            self.index += 1;
        }
    }

    fn parseOne(self: *ChallengeParser, allocator: Allocator) Error!Challenge {
        const scheme = try self.takeTokenAlloc(allocator);
        errdefer allocator.free(scheme);

        const had_whitespace = self.skipWhitespace();
        if (self.done() or self.input[self.index] == ',') {
            return .{ .scheme = scheme, .token68 = null, .parameters = try allocator.alloc(Parameter, 0) };
        }
        if (!had_whitespace) return error.MalformedChallenge;

        const start = self.index;
        _ = self.takeTokenSlice() catch return error.MalformedChallenge;
        _ = self.skipWhitespace();
        if (self.index < self.input.len and self.input[self.index] == '=' and !self.token68At(start)) {
            self.index = start;
            return .{
                .scheme = scheme,
                .token68 = null,
                .parameters = try self.parseParameters(allocator),
            };
        }

        self.index = start;
        const token68 = try self.takeToken68Alloc(allocator);
        errdefer allocator.free(token68);
        _ = self.skipWhitespace();
        if (!self.done() and self.input[self.index] != ',') return error.MalformedChallenge;
        return .{
            .scheme = scheme,
            .token68 = token68,
            .parameters = try allocator.alloc(Parameter, 0),
        };
    }

    fn token68At(self: *const ChallengeParser, start: usize) bool {
        var end = start;
        while (end < self.input.len and isToken68(self.input[end])) : (end += 1) {}
        if (end == start or (end < self.input.len and !isOws(self.input[end]) and self.input[end] != ',')) return false;
        const candidate = self.input[start..end];
        const padding = std.mem.indexOfScalar(u8, candidate, '=') orelse return false;
        for (candidate[padding..]) |byte| {
            if (byte != '=') return false;
        }
        return true;
    }

    fn parseParameters(self: *ChallengeParser, allocator: Allocator) Error![]Parameter {
        var parameters = std.array_list.Managed(Parameter).init(allocator);
        errdefer {
            for (parameters.items) |*parameter| parameter.deinit(allocator);
            parameters.deinit();
        }

        while (true) {
            if (parameters.items.len >= max_challenge_parameters) return error.TooManyChallenges;
            const name = try self.takeTokenAlloc(allocator);
            _ = self.skipWhitespace();
            if (self.index == self.input.len or self.input[self.index] != '=') {
                allocator.free(name);
                return error.MalformedChallenge;
            }
            self.index += 1;
            _ = self.skipWhitespace();
            const value = self.takeParameterValueAlloc(allocator) catch |err| {
                allocator.free(name);
                return err;
            };
            parameters.append(.{ .name = name, .value = value }) catch |err| {
                allocator.free(name);
                allocator.free(value);
                return err;
            };

            _ = self.skipWhitespace();
            if (self.done()) break;
            if (self.input[self.index] != ',') return error.MalformedChallenge;
            self.index += 1;
            _ = self.skipWhitespace();
            if (self.done()) break;

            // A comma begins another parameter only when a token followed by
            // optional whitespace and '=' follows it.  Otherwise it begins
            // the next challenge and is left for the outer parser.
            const next = self.index;
            _ = self.takeTokenSlice() catch return error.MalformedChallenge;
            _ = self.skipWhitespace();
            if (self.index < self.input.len and self.input[self.index] == '=') {
                self.index = next;
                continue;
            }
            self.index = next;
            break;
        }

        return parameters.toOwnedSlice();
    }

    fn takeParameterValueAlloc(self: *ChallengeParser, allocator: Allocator) Error![]u8 {
        if (self.index == self.input.len) return error.MalformedChallenge;
        if (self.input[self.index] != '"') return self.takeTokenAlloc(allocator);
        self.index += 1;
        var output = std.Io.Writer.Allocating.init(allocator);
        errdefer output.deinit();
        while (self.index < self.input.len) {
            const byte = self.input[self.index];
            self.index += 1;
            switch (byte) {
                '"' => return output.toOwnedSlice(),
                '\\' => {
                    if (self.index == self.input.len) return error.MalformedChallenge;
                    const escaped = self.input[self.index];
                    self.index += 1;
                    if (escaped == '\r' or escaped == '\n') return error.MalformedChallenge;
                    try output.writer.writeByte(escaped);
                },
                '\r', '\n' => return error.MalformedChallenge,
                else => try output.writer.writeByte(byte),
            }
        }
        return error.MalformedChallenge;
    }

    fn takeTokenAlloc(self: *ChallengeParser, allocator: Allocator) Error![]u8 {
        return allocator.dupe(u8, try self.takeTokenSlice());
    }

    fn takeTokenSlice(self: *ChallengeParser) Error![]const u8 {
        const start = self.index;
        while (self.index < self.input.len and isToken(self.input[self.index])) : (self.index += 1) {}
        if (self.index == start) return error.MalformedChallenge;
        return self.input[start..self.index];
    }

    fn takeToken68Alloc(self: *ChallengeParser, allocator: Allocator) Error![]u8 {
        const start = self.index;
        while (self.index < self.input.len and isToken68(self.input[self.index])) : (self.index += 1) {}
        if (self.index == start) return error.MalformedChallenge;
        return allocator.dupe(u8, self.input[start..self.index]);
    }
};

fn isOws(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn isToken(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn isToken68(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '-', '.', '_', '~', '+', '/', '=' => true,
        else => false,
    };
}

pub const Credential = struct {
    username: []u8,
    secret: []u8,

    pub fn deinit(self: *Credential, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.secret);
        allocator.free(self.username);
        allocator.free(self.secret);
        self.* = undefined;
    }
};

/// A credential a caller states rather than one discovery found. The bytes are
/// borrowed for the duration of the call that receives it, exactly like the
/// other borrowed option fields beside it, so a caller that holds a secret in
/// memory it already owns never hands ownership away to learn whether it was
/// accepted. `Credential` remains the owned form the receiver keeps.
pub const SuppliedCredential = struct {
    username: []const u8,
    secret: []const u8,

    /// Copies the borrowed bytes into allocator-owned memory. The result is
    /// wiped by `Credential.deinit`; the borrowed original is not, and wiping
    /// it stays the caller's business.
    pub fn toOwned(self: SuppliedCredential, allocator: Allocator) Allocator.Error!Credential {
        const username = try allocator.dupe(u8, self.username);
        errdefer allocator.free(username);
        const secret = try allocator.dupe(u8, self.secret);
        return .{ .username = username, .secret = secret };
    }
};

pub const ProcessResult = struct {
    stdout: []u8,

    pub fn deinit(self: *ProcessResult, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.stdout);
        allocator.free(self.stdout);
        self.* = undefined;
    }
};

/// Process execution is injectable so callers can test helper invocation
/// without placing credentials in a command line or requiring a helper binary.
pub const ProcessRunner = struct {
    context: ?*anyopaque = null,
    run: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        stdin: []const u8,
        max_output: usize,
    ) anyerror!ProcessResult = runProcess,
};

pub const CredentialOptions = struct {
    authfile: ?[]const u8 = null,
    process_runner: ProcessRunner = .{},
};

/// Searches registries' standard credential locations in deliberate order.
/// A configured helper wins over inline auth values in the same configuration.
pub fn findCredential(
    io: Io,
    allocator: Allocator,
    environ: std.process.Environ,
    authority: []const u8,
    repository: []const u8,
    options: CredentialOptions,
) !?Credential {
    var environment = try std.process.Environ.createMap(environ, allocator);
    defer environment.deinit();

    if (options.authfile) |path| {
        if (try findCredentialInFile(io, allocator, path, authority, repository, options.process_runner, true)) |credential| {
            return credential;
        }
    }
    if (environment.get("REGISTRY_AUTH_FILE")) |path| {
        if (try findCredentialInFile(io, allocator, path, authority, repository, options.process_runner, false)) |credential| {
            return credential;
        }
    }
    if (environment.get("XDG_RUNTIME_DIR")) |runtime_dir| {
        const path = try std.fs.path.join(allocator, &.{ runtime_dir, "containers", "auth.json" });
        defer allocator.free(path);
        if (try findCredentialInFile(io, allocator, path, authority, repository, options.process_runner, false)) |credential| {
            return credential;
        }
    }

    const home = environment.get("HOME");
    const xdg_config_home = environment.get("XDG_CONFIG_HOME") orelse if (home) |value|
        try std.fs.path.join(allocator, &.{ value, ".config" })
    else
        null;
    defer if (environment.get("XDG_CONFIG_HOME") == null) {
        if (xdg_config_home) |value| allocator.free(value);
    };
    if (xdg_config_home) |config_home| {
        const path = try std.fs.path.join(allocator, &.{ config_home, "containers", "auth.json" });
        defer allocator.free(path);
        if (try findCredentialInFile(io, allocator, path, authority, repository, options.process_runner, false)) |credential| {
            return credential;
        }
    }
    if (home) |home_path| {
        const docker_config = try std.fs.path.join(allocator, &.{ home_path, ".docker", "config.json" });
        defer allocator.free(docker_config);
        if (try findCredentialInFile(io, allocator, docker_config, authority, repository, options.process_runner, false)) |credential| {
            return credential;
        }
        const dockercfg = try std.fs.path.join(allocator, &.{ home_path, ".dockercfg" });
        defer allocator.free(dockercfg);
        if (try findCredentialInFile(io, allocator, dockercfg, authority, repository, options.process_runner, false)) |credential| {
            return credential;
        }
    }
    return null;
}

fn findCredentialInFile(
    io: Io,
    allocator: Allocator,
    path: []const u8,
    authority: []const u8,
    repository: []const u8,
    runner: ProcessRunner,
    required: bool,
) !?Credential {
    const bytes = readBoundedFile(io, allocator, path, max_auth_file_size) catch |err| switch (err) {
        error.FileNotFound => {
            if (required) return error.AuthFileNotFound;
            return null;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidAuthFile,
    };
    defer allocator.free(bytes);
    return parseCredentialFile(allocator, io, bytes, authority, repository, runner);
}

fn readBoundedFile(io: Io, allocator: Allocator, path: []const u8, limit: usize) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try Io.Dir.openFileAbsolute(io, path, .{})
    else
        try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = try file.length(io);
    if (size > limit or size > std.math.maxInt(usize)) return error.InvalidAuthFile;
    const bytes = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.InvalidAuthFile;
    return bytes;
}

fn parseCredentialFile(
    allocator: Allocator,
    io: Io,
    bytes: []const u8,
    authority: []const u8,
    repository: []const u8,
    runner: ProcessRunner,
) !?Credential {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return error.InvalidAuthFile;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidAuthFile,
    };

    if (root.get("credHelpers")) |helpers| {
        const helper_object = switch (helpers) {
            .object => |object| object,
            else => return error.InvalidAuthFile,
        };
        if (selectMostSpecific(helper_object, authority, repository)) |entry| {
            const helper = switch (entry.value) {
                .string => |value| value,
                else => return error.InvalidAuthFile,
            };
            return @as(?Credential, try runCredentialHelper(allocator, io, runner, helper, entry.key));
        }
    }
    if (root.get("credsStore")) |store| {
        const helper = switch (store) {
            .string => |value| value,
            else => return error.InvalidAuthFile,
        };
        if (helper.len != 0) {
            return @as(?Credential, try runCredentialHelper(
                allocator,
                io,
                runner,
                helper,
                globalCredentialHelperKey(authority),
            ));
        }
    }
    if (root.get("auths")) |auths| {
        const auth_object = switch (auths) {
            .object => |object| object,
            else => return error.InvalidAuthFile,
        };
        if (selectMostSpecific(auth_object, authority, repository)) |entry| {
            return parseInlineCredential(allocator, entry.value);
        }
    } else if (selectMostSpecific(root, authority, repository)) |entry| {
        // Legacy .dockercfg has auth entries at its top level.
        return parseInlineCredential(allocator, entry.value);
    }
    return null;
}

const ObjectEntry = struct {
    key: []const u8,
    value: std.json.Value,
};

fn selectMostSpecific(object: std.json.ObjectMap, authority: []const u8, repository: []const u8) ?ObjectEntry {
    var result: ?ObjectEntry = null;
    var score: usize = 0;
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        const candidate = entry.key_ptr.*;
        const candidate_score = credentialKeyScore(candidate, authority, repository) orelse continue;
        if (result == null or candidate_score > score) {
            result = .{ .key = candidate, .value = entry.value_ptr.* };
            score = candidate_score;
        }
    }
    return result;
}

fn credentialKeyScore(key: []const u8, authority: []const u8, repository: []const u8) ?usize {
    var candidate = key;
    if (std.mem.startsWith(u8, candidate, "https://")) candidate = candidate["https://".len..];
    if (std.mem.startsWith(u8, candidate, "http://")) candidate = candidate["http://".len..];
    while (candidate.len > 0 and candidate[candidate.len - 1] == '/') {
        candidate = candidate[0 .. candidate.len - 1];
    }
    if (candidate.len == 0) return null;

    const slash = std.mem.indexOfScalar(u8, candidate, '/');
    const candidate_host = if (slash) |index| candidate[0..index] else candidate;
    var candidate_path = if (slash) |index| candidate[index + 1 ..] else "";
    if (isDockerHubAlias(candidate_host) and
        (std.mem.eql(u8, candidate_path, "v1") or std.mem.eql(u8, candidate_path, "v2")))
    {
        candidate_path = "";
    }
    if (!sameRegistry(candidate_host, authority)) return null;
    if (candidate_path.len != 0 and
        (!std.mem.startsWith(u8, repository, candidate_path) or
            (repository.len != candidate_path.len and repository[candidate_path.len] != '/')))
    {
        return null;
    }
    return candidate_host.len + candidate_path.len;
}

fn sameRegistry(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right) or
        (isDockerHubAlias(left) and isDockerHubAlias(right));
}

fn isDockerHubAlias(value: []const u8) bool {
    return std.mem.eql(u8, value, "docker.io") or
        std.mem.eql(u8, value, "index.docker.io") or
        std.mem.eql(u8, value, "registry-1.docker.io");
}

fn globalCredentialHelperKey(authority: []const u8) []const u8 {
    return if (isDockerHubAlias(authority))
        "https://index.docker.io/v1/"
    else
        authority;
}

fn parseInlineCredential(allocator: Allocator, value: std.json.Value) !?Credential {
    const object = switch (value) {
        .object => |result| result,
        .null => return null,
        else => return error.InvalidAuthFile,
    };
    const auth_value = object.get("auth") orelse return null;
    const encoded = switch (auth_value) {
        .string => |result| result,
        else => return error.InvalidAuthFile,
    };
    if (encoded.len == 0) return null;
    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.InvalidAuthFile;
    if (decoded_size == 0 or decoded_size > max_helper_output_size) return error.InvalidAuthFile;
    const decoded = try allocator.alloc(u8, decoded_size);
    errdefer {
        std.crypto.secureZero(u8, decoded);
        allocator.free(decoded);
    }
    std.base64.standard.Decoder.decode(decoded, encoded) catch return error.InvalidAuthFile;
    const separator = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidCredential;
    if (separator == 0) return error.InvalidCredential;
    const username = try allocator.dupe(u8, decoded[0..separator]);
    errdefer allocator.free(username);
    const secret = try allocator.dupe(u8, decoded[separator + 1 ..]);
    std.crypto.secureZero(u8, decoded);
    allocator.free(decoded);
    return .{ .username = username, .secret = secret };
}

fn runCredentialHelper(
    allocator: Allocator,
    io: Io,
    runner: ProcessRunner,
    helper: []const u8,
    server_key: []const u8,
) !Credential {
    if (!validHelperName(helper)) return error.InvalidCredentialHelperName;
    const executable = try std.fmt.allocPrint(allocator, "docker-credential-{s}", .{helper});
    defer allocator.free(executable);
    const argv = [_][]const u8{ executable, "get" };
    var result = runner.run(runner.context, allocator, io, &argv, server_key, max_helper_output_size) catch return error.CredentialHelperFailed;
    defer result.deinit(allocator);
    if (result.stdout.len > max_helper_output_size) return error.CredentialHelperOutputTooLarge;
    return parseHelperOutput(allocator, result.stdout);
}

fn validHelperName(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return false;
    }
    return true;
}

fn parseHelperOutput(allocator: Allocator, bytes: []const u8) !Credential {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return error.InvalidCredentialHelperOutput;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.InvalidCredentialHelperOutput,
    };
    if (object.get("ServerURL")) |server_url| {
        if (server_url != .string or server_url.string.len == 0) return error.InvalidCredentialHelperOutput;
    }
    const username_value = object.get("Username") orelse return error.InvalidCredentialHelperOutput;
    const secret_value = object.get("Secret") orelse return error.InvalidCredentialHelperOutput;
    const username = switch (username_value) {
        .string => |value| value,
        else => return error.InvalidCredentialHelperOutput,
    };
    const secret = switch (secret_value) {
        .string => |value| value,
        else => return error.InvalidCredentialHelperOutput,
    };
    if (username.len == 0 or secret.len == 0) return error.InvalidCredentialHelperOutput;
    const owned_username = try allocator.dupe(u8, username);
    errdefer allocator.free(owned_username);
    return .{ .username = owned_username, .secret = try allocator.dupe(u8, secret) };
}

fn runProcess(
    _: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    stdin_data: []const u8,
    max_output: usize,
) !ProcessResult {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);

    var stdin = child.stdin.?;
    child.stdin = null;
    try stdin.writeStreamingAll(io, stdin_data);
    stdin.close(io);

    var streams_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var streams: Io.File.MultiReader = undefined;
    streams.init(allocator, io, streams_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    const stdout = streams.reader(0);
    const stderr = streams.reader(1);
    defer {
        std.crypto.secureZero(u8, stdout.buffered());
        std.crypto.secureZero(u8, stderr.buffered());
        streams.deinit();
    }
    while (streams.fill(256, .none)) |_| {
        if (stdout.buffered().len > max_output or stderr.buffered().len > max_output) {
            return error.CredentialHelperOutputTooLarge;
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
    try streams.checkAnyError();
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.CredentialHelperFailed,
        else => return error.CredentialHelperFailed,
    }
    const output = try streams.toOwnedSlice(0);
    errdefer {
        std.crypto.secureZero(u8, output);
        allocator.free(output);
    }
    if (output.len > max_output) return error.CredentialHelperOutputTooLarge;
    return .{ .stdout = output };
}

pub fn basicAuthorizationAlloc(allocator: Allocator, credential: Credential) ![]u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ credential.username, credential.secret });
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }
    const encoded_len = std.base64.standard.Encoder.calcSize(raw.len);
    const result = try allocator.alloc(u8, "Basic ".len + encoded_len);
    errdefer allocator.free(result);
    @memcpy(result[0.."Basic ".len], "Basic ");
    _ = std.base64.standard.Encoder.encode(result["Basic ".len..], raw);
    return result;
}

pub const Token = struct {
    value: []u8,
    expires_in: ?u64,

    pub fn deinit(self: *Token, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.value);
        allocator.free(self.value);
        self.* = undefined;
    }
};

/// Parses an OCI token response without retaining JSON parser buffers.
pub fn parseTokenResponse(allocator: Allocator, bytes: []const u8) Error!Token {
    if (bytes.len > max_token_response_size) return error.TokenResponseTooLarge;
    const Document = struct {
        token: ?[]const u8 = null,
        access_token: ?[]const u8 = null,
        expires_in: ?u64 = null,
    };
    var parsed = std.json.parseFromSlice(Document, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidTokenResponse;
    defer parsed.deinit();
    const value = parsed.value.token orelse parsed.value.access_token orelse return error.InvalidTokenResponse;
    if (!validBearerToken(value)) return error.InvalidTokenResponse;
    return .{ .value = try allocator.dupe(u8, value), .expires_in = parsed.value.expires_in };
}

fn validBearerToken(value: []const u8) bool {
    if (value.len == 0 or value.len > max_token_length) return false;
    var padded = false;
    for (value) |byte| {
        if (byte == '=') {
            padded = true;
            continue;
        }
        if (padded) return false;
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '-' and byte != '.' and byte != '_' and byte != '~' and
            byte != '+' and byte != '/')
        {
            return false;
        }
    }
    return !padded or value[0] != '=';
}

/// Builds a token URL preserving every challenged `scope` value.  Parameters
/// are RFC 3986 query encoded rather than interpolated into the URL.
pub fn buildBearerTokenUrlAlloc(
    allocator: Allocator,
    realm: []const u8,
    service: ?[]const u8,
    scopes: []const []const u8,
) Error![]u8 {
    const uri = std.Uri.parse(realm) catch return error.InvalidTokenRealm;
    if (!std.mem.eql(u8, uri.scheme, "https") and !std.mem.eql(u8, uri.scheme, "http")) return error.InvalidTokenRealm;
    if (std.mem.indexOfScalar(u8, realm, '#') != null) return error.InvalidTokenRealm;

    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try output.writer.writeAll(realm);
    var needs_separator = std.mem.indexOfScalar(u8, realm, '?') == null;
    if (service) |value| try appendQueryParameter(&output.writer, &needs_separator, "service", value);
    for (scopes) |scope| try appendQueryParameter(&output.writer, &needs_separator, "scope", scope);
    return output.toOwnedSlice();
}

fn appendQueryParameter(writer: *std.Io.Writer, needs_separator: *bool, name: []const u8, value: []const u8) !void {
    try writer.writeByte(if (needs_separator.*) '?' else '&');
    needs_separator.* = false;
    try writeQueryComponent(writer, name);
    try writer.writeByte('=');
    try writeQueryComponent(writer, value);
}

fn writeQueryComponent(writer: *std.Io.Writer, value: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~') {
            try writer.writeByte(byte);
        } else {
            try writer.writeByte('%');
            try writer.writeByte(hex[byte >> 4]);
            try writer.writeByte(hex[byte & 0x0f]);
        }
    }
}

pub const TokenCache = struct {
    allocator: Allocator,
    entries: std.array_list.Managed(Entry),

    const Entry = struct {
        realm: []u8,
        service: ?[]u8,
        scopes: [][]u8,
        token: []u8,
        expires_at: i64,

        fn deinit(self: *Entry, allocator: Allocator) void {
            allocator.free(self.realm);
            if (self.service) |value| allocator.free(value);
            for (self.scopes) |scope| allocator.free(scope);
            allocator.free(self.scopes);
            std.crypto.secureZero(u8, self.token);
            allocator.free(self.token);
            self.* = undefined;
        }
    };

    pub fn init(allocator: Allocator) TokenCache {
        return .{ .allocator = allocator, .entries = std.array_list.Managed(Entry).init(allocator) };
    }

    pub fn deinit(self: *TokenCache) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn get(
        self: *TokenCache,
        io: Io,
        realm: []const u8,
        service: ?[]const u8,
        scopes: []const []const u8,
    ) ?[]const u8 {
        const now = Io.Clock.real.now(io).toSeconds();
        for (self.entries.items) |entry| {
            if (entry.expires_at <= now + 10) continue;
            if (sameTokenKey(entry, realm, service, scopes)) return entry.token;
        }
        return null;
    }

    pub fn put(
        self: *TokenCache,
        io: Io,
        realm: []const u8,
        service: ?[]const u8,
        scopes: []const []const u8,
        token: Token,
    ) ![]const u8 {
        const now = Io.Clock.real.now(io).toSeconds();
        const ttl = @min(token.expires_in orelse default_token_ttl_seconds, max_token_ttl_seconds);
        const expires_at = std.math.add(i64, now, @intCast(ttl)) catch std.math.maxInt(i64);
        for (self.entries.items) |*entry| {
            if (!sameTokenKey(entry.*, realm, service, scopes)) continue;
            std.crypto.secureZero(u8, entry.token);
            self.allocator.free(entry.token);
            entry.token = try self.allocator.dupe(u8, token.value);
            entry.expires_at = expires_at;
            return entry.token;
        }

        var copied_scopes = try self.allocator.alloc([]u8, scopes.len);
        var copied_count: usize = 0;
        errdefer {
            for (copied_scopes[0..copied_count]) |scope| self.allocator.free(scope);
            self.allocator.free(copied_scopes);
        }
        for (scopes, 0..) |scope, index| {
            copied_scopes[index] = try self.allocator.dupe(u8, scope);
            copied_count += 1;
        }
        const realm_copy = try self.allocator.dupe(u8, realm);
        errdefer self.allocator.free(realm_copy);
        const service_copy = if (service) |value| try self.allocator.dupe(u8, value) else null;
        errdefer if (service_copy) |value| self.allocator.free(value);
        const token_copy = try self.allocator.dupe(u8, token.value);
        errdefer {
            std.crypto.secureZero(u8, token_copy);
            self.allocator.free(token_copy);
        }
        try self.entries.append(.{
            .realm = realm_copy,
            .service = service_copy,
            .scopes = copied_scopes,
            .token = token_copy,
            .expires_at = expires_at,
        });
        return self.entries.items[self.entries.items.len - 1].token;
    }

    pub fn invalidate(
        self: *TokenCache,
        realm: []const u8,
        service: ?[]const u8,
        scopes: []const []const u8,
    ) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (sameTokenKey(self.entries.items[index], realm, service, scopes)) {
                var removed = self.entries.orderedRemove(index);
                removed.deinit(self.allocator);
            } else {
                index += 1;
            }
        }
    }

    /// Drops all cached bearer material. Callers use this after a registry
    /// explicitly rejects the currently active token before performing the
    /// single permitted refresh.
    pub fn clear(self: *TokenCache) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
    }
};

fn sameTokenKey(entry: TokenCache.Entry, realm: []const u8, service: ?[]const u8, scopes: []const []const u8) bool {
    if (!std.mem.eql(u8, entry.realm, realm)) return false;
    if ((entry.service == null) != (service == null)) return false;
    if (entry.service) |value| {
        if (!std.mem.eql(u8, value, service.?)) return false;
    }
    if (entry.scopes.len != scopes.len) return false;
    for (entry.scopes, scopes) |left, right| {
        if (!std.mem.eql(u8, left, right)) return false;
    }
    return true;
}

test "WWW-Authenticate parser accepts quoted commas escapes and challenge lists" {
    var parsed = try parseChallenges(std.testing.allocator, &.{
        "Basic realm=\"basic\", Bearer realm=\"https://token.example/auth?x=1\", service=\"registry.example\", scope=\"repository:one:pull\", scope=\"repository:two:pull,push\", note=\"a\\\\b\\\"c\"",
        "Bearer realm=\"https://other.example/token\",scope=\"repository:three:pull\"",
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.challenges.len);
    try std.testing.expect(parsed.challenges[0].isScheme("basic"));
    try std.testing.expect(parsed.challenges[1].isScheme("Bearer"));
    try std.testing.expectEqualStrings("repository:two:pull,push", parsed.challenges[1].parameters[3].value);
    try std.testing.expectEqualStrings("a\\b\"c", parsed.challenges[1].parameter("note").?);
    try std.testing.expectEqualStrings("repository:three:pull", parsed.challenges[2].parameter("scope").?);
}

test "WWW-Authenticate parser accepts padded token68 credentials" {
    var parsed = try parseChallenges(std.testing.allocator, &.{"Negotiate YWJjZA=="});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.challenges.len);
    try std.testing.expectEqualStrings("YWJjZA==", parsed.challenges[0].token68.?);
}

test "WWW-Authenticate parser rejects malformed quoted and parameter syntax" {
    try std.testing.expectError(error.MalformedChallenge, parseChallenges(std.testing.allocator, &.{"Bearer realm=\"unterminated"}));
    try std.testing.expectError(error.MalformedChallenge, parseChallenges(std.testing.allocator, &.{"Basic realm=\"x\", =bad"}));
    try std.testing.expectError(error.MalformedChallenge, parseChallenges(std.testing.allocator, &.{"Basic realm=\"x\" trailing"}));
}

test "token URLs preserve scopes and escape query values" {
    const result = try buildBearerTokenUrlAlloc(
        std.testing.allocator,
        "https://token.example/auth?existing=yes",
        "registry example",
        &.{ "repository:one/image:pull", "repository:two/image:pull,push" },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "https://token.example/auth?existing=yes&service=registry%20example&scope=repository%3Aone%2Fimage%3Apull&scope=repository%3Atwo%2Fimage%3Apull%2Cpush",
        result,
    );
}

test "token cache keys every scope and honors expiry" {
    var cache = TokenCache.init(std.testing.allocator);
    defer cache.deinit();
    var token = try parseTokenResponse(std.testing.allocator, "{\"access_token\":\"first\",\"expires_in\":3600}");
    defer token.deinit(std.testing.allocator);
    _ = try cache.put(std.testing.io, "https://token.example", "registry", &.{ "a", "b" }, token);
    try std.testing.expectEqualStrings("first", cache.get(std.testing.io, "https://token.example", "registry", &.{ "a", "b" }).?);
    try std.testing.expect(cache.get(std.testing.io, "https://token.example", "registry", &.{ "b", "a" }) == null);
    cache.invalidate("https://token.example", "registry", &.{ "a", "b" });
    try std.testing.expect(cache.get(std.testing.io, "https://token.example", "registry", &.{ "a", "b" }) == null);
}

test "token responses only accept bounded RFC 6750 bearer values" {
    inline for ([_][]const u8{
        "{\"token\":\"good\\r\\nInjected: value\"}",
        "{\"token\":\"good token\"}",
        "{\"token\":\"good=token\"}",
        "{\"token\":\"=good\"}",
        "{\"token\":\"good\\u0001token\"}",
    }) |document| {
        try std.testing.expectError(error.InvalidTokenResponse, parseTokenResponse(std.testing.allocator, document));
    }

    var jwt = try parseTokenResponse(
        std.testing.allocator,
        "{\"access_token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature\"}",
    );
    defer jwt.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature", jwt.value);

    var padded = try parseTokenResponse(std.testing.allocator, "{\"token\":\"YWJjZA==\"}");
    defer padded.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("YWJjZA==", padded.value);

    const oversized_value = try std.testing.allocator.alloc(u8, max_token_length + 1);
    defer std.testing.allocator.free(oversized_value);
    @memset(oversized_value, 'a');
    const oversized_document = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"token\":\"{s}\"}}",
        .{oversized_value},
    );
    defer std.testing.allocator.free(oversized_document);
    try std.testing.expectError(error.InvalidTokenResponse, parseTokenResponse(std.testing.allocator, oversized_document));
}

test "token responses without expires_in receive a conservative cache lifetime" {
    var cache = TokenCache.init(std.testing.allocator);
    defer cache.deinit();
    var token = try parseTokenResponse(std.testing.allocator, "{\"token\":\"uncached-before\"}");
    defer token.deinit(std.testing.allocator);
    _ = try cache.put(std.testing.io, "https://token.example", null, &.{}, token);
    try std.testing.expectEqualStrings(
        "uncached-before",
        cache.get(std.testing.io, "https://token.example", null, &.{}).?,
    );
}

test "credential helper runner receives the registry only on stdin" {
    const Context = struct {
        seen: bool = false,

        fn run(
            raw_context: ?*anyopaque,
            allocator: Allocator,
            _: Io,
            argv: []const []const u8,
            stdin_data: []const u8,
            _: usize,
        ) !ProcessResult {
            const context: *@This() = @ptrCast(@alignCast(raw_context.?));
            try std.testing.expectEqual(@as(usize, 2), argv.len);
            try std.testing.expectEqualStrings("docker-credential-test", argv[0]);
            try std.testing.expectEqualStrings("get", argv[1]);
            try std.testing.expectEqualStrings("registry.example/team/image", stdin_data);
            context.seen = true;
            return .{ .stdout = try allocator.dupe(u8, "{\"ServerURL\":\"registry.example\",\"Username\":\"user\",\"Secret\":\"secret\"}") };
        }
    };
    var context = Context{};
    var credential = try runCredentialHelper(std.testing.allocator, std.testing.io, .{
        .context = &context,
        .run = Context.run,
    }, "test", "registry.example/team/image");
    defer credential.deinit(std.testing.allocator);
    try std.testing.expect(context.seen);
    try std.testing.expectEqualStrings("user", credential.username);
    try std.testing.expectEqualStrings("secret", credential.secret);
}

test "global Docker Hub credential helpers receive the canonical stdin key" {
    const io = std.testing.io;
    const path = "test-oci-creds-store.json";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "{\"credsStore\":\"test\"}" });
    const Context = struct {
        calls: usize = 0,

        fn run(
            raw_context: ?*anyopaque,
            allocator: Allocator,
            _: Io,
            argv: []const []const u8,
            stdin_data: []const u8,
            _: usize,
        ) !ProcessResult {
            const context: *@This() = @ptrCast(@alignCast(raw_context.?));
            try std.testing.expectEqual(@as(usize, 2), argv.len);
            try std.testing.expectEqualStrings("docker-credential-test", argv[0]);
            try std.testing.expectEqualStrings("get", argv[1]);
            for (argv) |argument| {
                try std.testing.expect(std.mem.indexOf(u8, argument, "index.docker.io") == null);
            }
            try std.testing.expectEqualStrings("https://index.docker.io/v1/", stdin_data);
            context.calls += 1;
            return .{ .stdout = try allocator.dupe(
                u8,
                "{\"ServerURL\":\"https://index.docker.io/v1/\",\"Username\":\"user\",\"Secret\":\"secret\"}",
            ) };
        }
    };
    var context = Context{};
    inline for ([_][]const u8{ "docker.io", "index.docker.io", "registry-1.docker.io" }) |authority| {
        var credential = (try findCredential(
            io,
            std.testing.allocator,
            std.process.Environ.empty,
            authority,
            "library/busybox",
            .{
                .authfile = path,
                .process_runner = .{ .context = &context, .run = Context.run },
            },
        )).?;
        credential.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 3), context.calls);
}

test "explicit authfile chooses the most specific Docker-compatible key" {
    const io = std.testing.io;
    const path = "test-oci-authfile.json";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data =
        \\{"auths":{"https://index.docker.io/v1/":{"auth":"ZG9ja2VyOnBhc3M="},"registry.example/team":{"auth":"dGVhbTpzZWNyZXQ="}}}
    });
    var repository_credential = (try findCredential(
        io,
        std.testing.allocator,
        std.process.Environ.empty,
        "registry.example",
        "team/image",
        .{ .authfile = path },
    )).?;
    defer repository_credential.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("team", repository_credential.username);
    try std.testing.expectEqualStrings("secret", repository_credential.secret);

    var docker_credential = (try findCredential(
        io,
        std.testing.allocator,
        std.process.Environ.empty,
        "registry-1.docker.io",
        "library/busybox",
        .{ .authfile = path },
    )).?;
    defer docker_credential.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("docker", docker_credential.username);
    try std.testing.expectEqualStrings("pass", docker_credential.secret);
}
