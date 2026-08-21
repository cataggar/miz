const std = @import("std");
const vmiz = @import("vmiz");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const Digest = vmiz.artifact_pipeline.Digest;

pub const Mode = union(enum) {
    local_key: struct {
        private_key_path: []const u8,
    },
    external_command: struct {
        executable_path: []const u8,
        argument: ?[]const u8 = null,
    },

    pub fn name(self: Mode) []const u8 {
        return switch (self) {
            .local_key => "local-key",
            .external_command => "external-command",
        };
    }
};

pub const Config = struct {
    certificate_path: []const u8,
    expected_certificate_sha256: Digest,
    mode: Mode,
};

pub const Certificate = struct {
    der: []u8,
    sha256: Digest,
    details: []u8,

    pub fn deinit(self: *Certificate, allocator: Allocator) void {
        allocator.free(self.der);
        allocator.free(self.details);
        self.* = undefined;
    }
};

pub const SignedUki = struct {
    bytes: []u8,
    unsigned_sha256: Digest,
    signed_sha256: Digest,
    provider_metadata: ?ProviderMetadata = null,

    pub fn deinit(self: *SignedUki, allocator: Allocator) void {
        allocator.free(self.bytes);
        if (self.provider_metadata) |*metadata| metadata.deinit(allocator);
        self.* = undefined;
    }
};

pub const ProviderMetadata = struct {
    provider: []u8,
    endpoint: []u8,
    account: []u8,
    profile: []u8,
    operation_id: []u8,
    signing_certificate_sha256: Digest,
    enrolled_certificate_sha256: Digest,

    pub fn deinit(self: *ProviderMetadata, allocator: Allocator) void {
        allocator.free(self.provider);
        allocator.free(self.endpoint);
        allocator.free(self.account);
        allocator.free(self.profile);
        allocator.free(self.operation_id);
        self.* = undefined;
    }

    pub fn clone(
        self: ProviderMetadata,
        allocator: Allocator,
    ) !ProviderMetadata {
        const provider = try allocator.dupe(u8, self.provider);
        errdefer allocator.free(provider);
        const endpoint = try allocator.dupe(u8, self.endpoint);
        errdefer allocator.free(endpoint);
        const account = try allocator.dupe(u8, self.account);
        errdefer allocator.free(account);
        const profile = try allocator.dupe(u8, self.profile);
        errdefer allocator.free(profile);
        const operation_id = try allocator.dupe(u8, self.operation_id);
        errdefer allocator.free(operation_id);
        return .{
            .provider = provider,
            .endpoint = endpoint,
            .account = account,
            .profile = profile,
            .operation_id = operation_id,
            .signing_certificate_sha256 = self.signing_certificate_sha256,
            .enrolled_certificate_sha256 = self.enrolled_certificate_sha256,
        };
    }
};

const max_private_key_bytes = 64 * 1024;
const max_provider_metadata_bytes = 16 * 1024;

pub fn parseFingerprint(value: []const u8) error{InvalidCertificateFingerprint}!Digest {
    return vmiz.artifact_pipeline.parseSha256(value) catch
        return error.InvalidCertificateFingerprint;
}

pub fn prepareScratchDirectory(io: Io, path: []const u8) !void {
    try Dir.cwd().deleteTree(io, path);
    try Dir.cwd().createDirPath(io, path);
    var directory = try Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer directory.close(io);
    try directory.setPermissions(io, .fromMode(0o700));
}

/// Loads the declared signing certificate, checks its fingerprint against the
/// one the release is pinned to, and renders a short human description of it.
/// The normalization to DER, the structural validation, and the description
/// are all this project's own code; nothing here runs `openssl`.
pub fn prepareCertificate(
    allocator: Allocator,
    io: Io,
    config: Config,
) !Certificate {
    var certificate = vmiz.uki_signing.loadCertificateAlloc(
        allocator,
        io,
        .{ .host_path = config.certificate_path },
    ) catch return error.InvalidSigningCertificate;
    defer certificate.deinit(allocator);
    if (certificate.der.len == 0) return error.EmptyCertificate;
    if (!std.mem.eql(u8, &certificate.sha256, &config.expected_certificate_sha256))
        return error.CertificateFingerprintMismatch;

    const details = try vmiz.authenticode.describeCertificateAlloc(
        allocator,
        certificate.der,
    );
    errdefer allocator.free(details);
    if (details.len == 0) return error.EmptyCertificateDetails;

    const der = try allocator.dupe(u8, certificate.der);
    return .{
        .der = der,
        .sha256 = certificate.sha256,
        .details = details,
    };
}

pub fn signUkiAlloc(
    allocator: Allocator,
    io: Io,
    config: Config,
    scratch_path: []const u8,
    base_environ: *const std.process.Environ.Map,
    index: usize,
    architecture: []const u8,
    flavor: []const u8,
    unsigned_bytes: []const u8,
) !SignedUki {
    const signed_bytes = switch (config.mode) {
        .local_key => |local| try signWithLocalKeyAlloc(
            allocator,
            io,
            config,
            local.private_key_path,
            unsigned_bytes,
        ),
        .external_command => |external| try signWithProviderAlloc(
            allocator,
            io,
            config,
            external,
            scratch_path,
            base_environ,
            index,
            architecture,
            flavor,
            unsigned_bytes,
        ),
    };
    errdefer allocator.free(signed_bytes.bytes);

    // A second, independent pass over the finished bytes: whichever path
    // produced them, `verifyBytes` re-derives the signer from the image and
    // checks the RSA signature against the enrolled certificate's own key, so
    // a signature that does not verify never leaves this function.
    try verifyBytes(allocator, io, config, signed_bytes.bytes);

    return .{
        .bytes = signed_bytes.bytes,
        .unsigned_sha256 = vmiz.artifact_pipeline.sha256Bytes(unsigned_bytes),
        .signed_sha256 = vmiz.artifact_pipeline.sha256Bytes(signed_bytes.bytes),
        .provider_metadata = signed_bytes.provider_metadata,
    };
}

const SignedBytes = struct {
    bytes: []u8,
    provider_metadata: ?ProviderMetadata = null,
};

/// Signs with a private key on this machine, which is what a development or
/// self-signed build does. The library has no equivalent and should not grow
/// one: it would mean a key on the build host, which is the arrangement
/// production signing exists to avoid.
///
/// The RSA signing is this project's own (`authenticode.signPeRsaSha256Alloc`),
/// so a local build depends on no external `sbsign`. That function embeds the
/// signature and then verifies it against the certificate before returning, so
/// a key and certificate that do not belong together fail here.
fn signWithLocalKeyAlloc(
    allocator: Allocator,
    io: Io,
    config: Config,
    private_key_path: []const u8,
    unsigned_bytes: []const u8,
) !SignedBytes {
    var certificate = vmiz.uki_signing.loadCertificateAlloc(
        allocator,
        io,
        .{ .host_path = config.certificate_path },
    ) catch return error.InvalidSigningCertificate;
    defer certificate.deinit(allocator);
    if (!std.mem.eql(u8, &certificate.sha256, &config.expected_certificate_sha256))
        return error.CertificateFingerprintMismatch;

    const key_file = Dir.cwd().readFileAlloc(
        io,
        private_key_path,
        allocator,
        .limited(max_private_key_bytes),
    ) catch return error.InvalidSigningPrivateKey;
    defer {
        @memset(key_file, 0);
        allocator.free(key_file);
    }
    const key_der = if (std.mem.indexOf(u8, key_file, "PRIVATE KEY-----") != null)
        vmiz.authenticode.decodePrivateKeyPemAlloc(allocator, key_file) catch
            return error.InvalidSigningPrivateKey
    else
        try allocator.dupe(u8, key_file);
    defer {
        @memset(key_der, 0);
        allocator.free(key_der);
    }

    const signed_bytes = vmiz.authenticode.signPeRsaSha256Alloc(
        allocator,
        unsigned_bytes,
        key_der,
        certificate.der,
    ) catch return error.LocalKeySigningFailed;
    errdefer allocator.free(signed_bytes);
    try verifyPayloads(allocator, unsigned_bytes, signed_bytes);
    return .{ .bytes = signed_bytes };
}

/// Runs the external provider protocol, which the library owns.
///
/// Everything about the exchange -- the variables, the scratch files, and the
/// check that what came back is a signature over the bytes that went out --
/// is `vmiz.uki_signing`'s, so that a release built by this script and an
/// image built by the library are signed by the same code. What stays here is
/// what a release builder knows and a library does not: the flavor it is
/// building, and which signing service it is willing to accept.
fn signWithProviderAlloc(
    allocator: Allocator,
    io: Io,
    config: Config,
    external: anytype,
    scratch_path: []const u8,
    base_environ: *const std.process.Environ.Map,
    index: usize,
    architecture: []const u8,
    flavor: []const u8,
    unsigned_bytes: []const u8,
) !SignedBytes {
    var certificate = vmiz.uki_signing.loadCertificateAlloc(
        allocator,
        io,
        .{ .host_path = config.certificate_path },
    ) catch return error.InvalidSigningCertificate;
    defer certificate.deinit(allocator);
    if (!std.mem.eql(u8, &certificate.sha256, &config.expected_certificate_sha256))
        return error.CertificateFingerprintMismatch;

    var environment = try base_environ.clone(allocator);
    defer environment.deinit();
    try environment.put("VMIZ_UKI_FLAVOR", flavor);

    const provider_scratch = try std.fmt.allocPrint(
        allocator,
        "{s}/provider-{d}",
        .{ scratch_path, index },
    );
    defer allocator.free(provider_scratch);
    defer Dir.cwd().deleteTree(io, provider_scratch) catch {};

    var signer = try vmiz.uki_signing.ExternalSigner.init(allocator, io, .{
        .command = .{
            .executable_path = external.executable_path,
            .argument = external.argument,
        },
        .certificate = certificate,
        .scratch_path = provider_scratch,
        .architecture = architecture,
        .base_environment = .{ .map = &environment },
    });
    defer signer.deinit();

    // No ESP path: this script signs bytes it read out of a finished image and
    // writes them back itself, so the library has nothing to record here.
    const signed_bytes = signer.signer().sign(allocator, .{
        .esp_paths = &.{},
        .unsigned = unsigned_bytes,
    }) catch |err| {
        if (signer.provider_error) |name|
            std.debug.print("signing command failed: {s}\n", .{name});
        return err;
    };
    errdefer allocator.free(signed_bytes);

    const records = signer.signatures();
    if (records.len != 1) return error.SigningCommandFailed;
    const metadata = if (records[0].provider) |value|
        try acceptProviderMetadata(allocator, value)
    else
        null;
    return .{ .bytes = signed_bytes, .provider_metadata = metadata };
}

/// Checks that the provider that answered is one a release may be signed by,
/// and copies what it said.
///
/// The library already refused metadata that is malformed or names a
/// certificate other than the declared one. This adds the part that is a
/// release policy rather than a protocol rule: that the service was Azure
/// Artifact Signing, reached at an endpoint that is one, and that the account,
/// profile, and operation identify a real operation there.
fn acceptProviderMetadata(
    allocator: Allocator,
    value: vmiz.uki_signing.ProviderMetadata,
) !ProviderMetadata {
    if (!std.mem.eql(u8, value.provider, "azure-artifact-signing") or
        !validArtifactSigningEndpoint(value.endpoint) or
        !validProviderResourceName(value.account) or
        !validProviderResourceName(value.profile) or
        !isUuid(value.operation_id))
    {
        return error.InvalidSigningProviderMetadata;
    }
    const provider = try allocator.dupe(u8, value.provider);
    errdefer allocator.free(provider);
    const endpoint = try allocator.dupe(u8, value.endpoint);
    errdefer allocator.free(endpoint);
    const account = try allocator.dupe(u8, value.account);
    errdefer allocator.free(account);
    const profile = try allocator.dupe(u8, value.profile);
    errdefer allocator.free(profile);
    const operation_id = try allocator.dupe(u8, value.operation_id);
    return .{
        .provider = provider,
        .endpoint = endpoint,
        .account = account,
        .profile = profile,
        .operation_id = operation_id,
        .signing_certificate_sha256 = value.signing_certificate_sha256,
        .enrolled_certificate_sha256 = value.enrolled_certificate_sha256,
    };
}

fn validArtifactSigningEndpoint(value: []const u8) bool {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, value, prefix) or
        std.mem.endsWith(u8, value, "/") or
        std.mem.indexOfAny(u8, value, "?#% \t\r\n") != null)
    {
        return false;
    }
    const host = value[prefix.len..];
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, '/') != null or
        !std.mem.endsWith(u8, host, ".codesigning.azure.net"))
    {
        return false;
    }
    for (host) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or
            byte == '-' or byte == '.'))
        {
            return false;
        }
    }
    return true;
}

fn validProviderResourceName(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or
            byte == '_' or byte == '.'))
        {
            return false;
        }
    }
    return true;
}

fn isUuid(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) {
            return false;
        }
    }
    return true;
}

/// Verifies finished signed bytes natively: the embedded Authenticode signature
/// must be a valid RSA/SHA-256 signature over this image, and the certificate
/// it was made by must be, byte for byte, the enrolled certificate this release
/// is pinned to. This is the replacement for `sbverify`, and unlike it, it
/// checks the signer's identity rather than only that some signature verifies.
pub fn verifyBytes(
    allocator: Allocator,
    io: Io,
    config: Config,
    signed_bytes: []const u8,
) !void {
    const signer = vmiz.authenticode.verifyRsaSha256(signed_bytes) catch
        return error.SignatureVerificationFailed;

    var certificate = vmiz.uki_signing.loadCertificateAlloc(
        allocator,
        io,
        .{ .host_path = config.certificate_path },
    ) catch return error.InvalidSigningCertificate;
    defer certificate.deinit(allocator);
    if (!std.mem.eql(u8, &certificate.sha256, &config.expected_certificate_sha256))
        return error.CertificateFingerprintMismatch;

    // "Verified" is only meaningful against a known certificate: the signer the
    // signature names must be the enrolled one, not merely a well-formed one.
    if (!std.mem.eql(u8, signer.certificate_der, certificate.der))
        return error.SignerCertificateMismatch;
    const signer_digest = vmiz.artifact_pipeline.sha256Bytes(signer.certificate_der);
    if (!std.mem.eql(u8, &signer_digest, &config.expected_certificate_sha256))
        return error.SignerCertificateMismatch;
}

fn verifyPayloads(
    allocator: Allocator,
    unsigned_bytes: []const u8,
    signed_bytes: []const u8,
) !void {
    var unsigned = try vmiz.uki.inspect(allocator, unsigned_bytes);
    defer unsigned.deinit(allocator);
    var signed = try vmiz.uki.inspect(allocator, signed_bytes);
    defer signed.deinit(allocator);

    if (signed.security_directory == null) return error.MissingSecurityDirectory;
    if (unsigned.machine != signed.machine or unsigned.subsystem != signed.subsystem)
        return error.SignedPeIdentityChanged;
    if (unsigned.sections.len != signed.sections.len)
        return error.SignedPeSectionsChanged;
    for (unsigned.sections, signed.sections) |before, after| {
        if (!std.mem.eql(u8, before.nameSlice(), after.nameSlice()) or
            !std.mem.eql(u8, before.contents, after.contents) or
            before.virtual_size != after.virtual_size or
            before.raw_size != after.raw_size or
            before.raw_offset != after.raw_offset)
        {
            return error.SignedPeSectionsChanged;
        }
    }
}

test "signing mode names are stable provenance values" {
    try std.testing.expectEqualStrings("local-key", (Mode{ .local_key = .{
        .private_key_path = "test.key",
    } }).name());
    try std.testing.expectEqualStrings("external-command", (Mode{ .external_command = .{
        .executable_path = "/test/signer",
        .argument = "sign",
    } }).name());
}

test "certificate fingerprints accept canonical SHA-256 forms" {
    const expected = [_]u8{0x11} ** 32;
    try std.testing.expectEqual(
        expected,
        try parseFingerprint("1111111111111111111111111111111111111111111111111111111111111111"),
    );
    try std.testing.expectEqual(
        expected,
        try parseFingerprint("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
    );
    try std.testing.expectError(
        error.InvalidCertificateFingerprint,
        parseFingerprint("1111"),
    );
}
