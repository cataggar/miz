//! Drives a declared UKI signing provider and checks what it hands back.
//!
//! miz never holds a private key and this module does not change that. It
//! gives the provider an unsigned PE and the certificate that provider is
//! required to have signed with, and then re-derives from the returned bytes
//! everything it goes on to assert. `authenticode.zig` states the same rule
//! from the other side: it builds the CMS but never performs the key
//! operation. So the key stays wherever the provider keeps it -- in the
//! `miz sign` model, in Azure Artifact Signing, reachable only by a
//! short-lived token the provider exchanges for itself.
//!
//! What is checked is what can be checked without a trust store: the payload
//! came back unchanged, a certificate table is now present, the signature
//! commits to exactly the bytes that were handed over, and the signer is the
//! declared certificate. What is deliberately not checked is whether any of
//! that should be believed -- the RSA signature is not verified and no chain
//! is built, the same line `uki_certificate.zig` draws.

const std = @import("std");

const artifact_pipeline = @import("artifact_pipeline.zig");
const authenticode = @import("authenticode.zig");
const uki = @import("uki.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const Digest = artifact_pipeline.Digest;

const max_certificate_bytes = 1024 * 1024;
const max_signature_overhead = 4 * 1024 * 1024;
const max_provider_metadata_bytes = 16 * 1024;
const max_command_output_bytes = 64 * 1024;
const signing_command_timeout_seconds = 5 * 60;

/// Everything that can go wrong between handing an image to a provider and
/// accepting what came back. A closed set, so a caller that embeds signing in
/// a larger operation still has an error union that names each failure.
pub const Error = Allocator.Error || error{
    /// The provider ran and did not succeed, or produced no output file.
    SigningProviderFailed,
    /// The provider's identity changed between two images of the same run.
    SigningProviderIdentityChanged,
    /// The provider reported metadata that is not the documented shape, or
    /// that names a certificate other than the declared one.
    InvalidSigningProviderMetadata,
    /// The scratch directory the provider exchanges files through could not
    /// be prepared, written or read.
    SigningWorkspaceFailed,
    /// The declared certificate is not a certificate.
    InvalidSigningCertificate,
    /// What came back is not a PE this module can read.
    InvalidSignedImage,
    /// What came back carries no certificate table.
    UnsignedResult,
    /// What came back is a different image: a changed machine, subsystem,
    /// section table or section payload.
    SignedImageChanged,
    /// The signature does not cover the bytes that were handed over.
    SignatureCoversOtherBytes,
    /// The signature names a signer other than the declared certificate.
    SignerCertificateMismatch,
};

/// Where a signing certificate's bytes come from.
///
/// A certificate is public, so unlike a credential it may be carried by value.
/// This mirrors `customize.TrustSource`, which allows the same two shapes for
/// the same reason, and is deliberately not `customize.CredentialSource`:
/// there is no private key here for a plan hash to turn into an oracle.
pub const CertificateSource = union(enum) {
    inline_bytes: []const u8,
    host_path: []const u8,
};

/// A signing certificate in both the form the provider protocol needs and the
/// form a signature carries, so neither has to be re-derived at a comparison.
pub const Certificate = struct {
    der: []u8,
    pem: []u8,
    sha256: Digest,

    pub fn deinit(self: *Certificate, allocator: Allocator) void {
        allocator.free(self.der);
        allocator.free(self.pem);
        self.* = undefined;
    }
};

/// A provider invoked as a host command, exchanging files through a scratch
/// directory and configured entirely through the environment.
///
/// This is the protocol `miz sign` already implements and the Azure Linux
/// release builder already uses, rather than a second one: `MIZ_UKI_UNSIGNED`,
/// `MIZ_UKI_SIGNED`, `MIZ_UKI_CERTIFICATE`, `MIZ_UKI_UNSIGNED_SHA256` and
/// `MIZ_UKI_CERTIFICATE_SHA256` name the exchange; `MIZ_UKI_ARCHITECTURE`
/// and `MIZ_UKI_SIGNING_METADATA` are advisory.
pub const ExternalCommand = struct {
    executable_path: []const u8,
    argument: ?[]const u8 = null,
};

pub const Provider = union(enum) {
    external_command: ExternalCommand,

    pub fn name(self: Provider) []const u8 {
        return switch (self) {
            .external_command => "external-command",
        };
    }
};

/// What a provider said about itself, in the shape the `miz sign` protocol
/// already defines. Absent when the provider wrote no metadata file, which is
/// how a signer that is merely a local command reports having no service
/// identity to state.
pub const ProviderMetadata = struct {
    provider: []const u8,
    endpoint: []const u8,
    account: []const u8,
    profile: []const u8,
    operation_id: []const u8,
    signing_certificate_sha256: Digest,
    enrolled_certificate_sha256: Digest,
};

/// What one signing operation turned out to be.
///
/// Every field is observed rather than assumed. `image_sha256` in particular
/// is read out of the returned signature and checked against the image, so it
/// records what the signature covers rather than what it was meant to cover.
/// The key is not here and is not representable.
pub const SignatureRecord = struct {
    /// Every path in the ESP these exact bytes were written to, in write
    /// order. A `uki_only` image writes the same signed bytes twice, and two
    /// records for one signature would read as two signing operations.
    esp_paths: []const []const u8,
    unsigned_sha256: Digest,
    signed_sha256: Digest,
    signed_size: u64,
    /// The digest the signature commits to, equal to the Authenticode digest
    /// of both the unsigned and the signed image.
    image_sha256: Digest,
    certificate_sha256: Digest,
    signer_subject_der: []const u8,
    signer_issuer_der: []const u8,
    signer_serial_number: []const u8,
    provider: ?ProviderMetadata = null,
};

/// A request to sign one image, naming every destination the bytes are bound
/// for so that one signing operation covers all of them.
pub const SignRequest = struct {
    esp_paths: []const []const u8,
    unsigned: []const u8,
};

/// The signing step, as the module that generates UKIs sees it.
///
/// An injected function rather than a concrete signer, so `bootconfig` keeps
/// generating PE images without gaining the ability to run host commands, and
/// so a test can prove the wiring without a signing service.
pub const Signer = struct {
    context: ?*anyopaque,
    signFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        request: SignRequest,
    ) Error![]u8,

    pub fn sign(
        self: Signer,
        allocator: Allocator,
        request: SignRequest,
    ) Error![]u8 {
        return self.signFn(self.context, allocator, request);
    }
};

/// Reads a declared certificate, in PEM or DER, and normalizes it to both.
pub fn loadCertificateAlloc(
    allocator: Allocator,
    io: Io,
    source: CertificateSource,
) Error!Certificate {
    const bytes = switch (source) {
        .inline_bytes => |value| try allocator.dupe(u8, value),
        .host_path => |path| Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(max_certificate_bytes),
        ) catch return error.InvalidSigningCertificate,
    };
    defer allocator.free(bytes);
    if (bytes.len == 0) return error.InvalidSigningCertificate;

    // PEM is what the provider protocol passes by path and what a caller is
    // most likely to hold; DER is accepted because that is what a signature
    // carries, and refusing the form the comparison is made in would be an
    // arbitrary asymmetry.
    const der = if (std.mem.indexOf(u8, bytes, "-----BEGIN CERTIFICATE-----") != null)
        authenticode.decodePemCertificateAlloc(allocator, bytes) catch
            return error.InvalidSigningCertificate
    else blk: {
        authenticode.validateX509CertificateDer(bytes) catch
            return error.InvalidSigningCertificate;
        break :blk try allocator.dupe(u8, bytes);
    };
    errdefer allocator.free(der);
    const pem = authenticode.encodePemCertificateAlloc(allocator, der) catch
        return error.InvalidSigningCertificate;
    return .{
        .der = der,
        .pem = pem,
        .sha256 = artifact_pipeline.sha256Bytes(der),
    };
}

/// What a check of a returned image established, all of it re-derived from
/// the bytes rather than taken from the provider.
pub const Verification = struct {
    image_sha256: Digest,
    signer_subject_der: []const u8,
    signer_issuer_der: []const u8,
    signer_serial_number: []const u8,
};

/// Checks that a provider signed the image it was given, with the certificate
/// it was told to use, and changed nothing else about it.
///
/// The returned slices borrow `signed`. This establishes what the signature is
/// over and who it names; it is not a trust decision, and neither the
/// signature nor any certificate chain is verified.
pub fn verifySigned(
    allocator: Allocator,
    unsigned: []const u8,
    signed: []const u8,
    certificate: Certificate,
) Error!Verification {
    var before = uki.inspect(allocator, unsigned) catch return error.InvalidSignedImage;
    defer before.deinit(allocator);
    var after = uki.inspect(allocator, signed) catch return error.InvalidSignedImage;
    defer after.deinit(allocator);

    if (after.security_directory == null) return error.UnsignedResult;
    if (before.machine != after.machine or before.subsystem != after.subsystem)
        return error.SignedImageChanged;
    if (before.sections.len != after.sections.len) return error.SignedImageChanged;
    for (before.sections, after.sections) |section_before, section_after| {
        if (!std.mem.eql(u8, section_before.nameSlice(), section_after.nameSlice()) or
            !std.mem.eql(u8, section_before.contents, section_after.contents) or
            section_before.virtual_size != section_after.virtual_size or
            section_before.raw_size != section_after.raw_size or
            section_before.raw_offset != section_after.raw_offset)
        {
            return error.SignedImageChanged;
        }
    }

    // A provider that signed a stale file would pass every check above: the
    // sections it returned are the ones it was given, because it copied them.
    // Only comparing what the signature covers with what the image is catches
    // it, which is why this is not optional.
    const image_digest = authenticode.imageSha256(signed) catch
        return error.InvalidSignedImage;
    const claimed = authenticode.embeddedImageSha256(signed) catch
        return error.InvalidSignedImage;
    if (!std.mem.eql(u8, &image_digest, &claimed))
        return error.SignatureCoversOtherBytes;
    const unsigned_image_digest = authenticode.imageSha256(unsigned) catch
        return error.InvalidSignedImage;
    if (!std.mem.eql(u8, &image_digest, &unsigned_image_digest))
        return error.SignatureCoversOtherBytes;

    const signer = authenticode.embeddedSigner(signed) catch
        return error.InvalidSignedImage;
    if (!std.mem.eql(u8, signer.certificate_der, certificate.der))
        return error.SignerCertificateMismatch;
    return .{
        .image_sha256 = image_digest,
        .signer_subject_der = signer.subject_der,
        .signer_issuer_der = signer.issuer_der,
        .signer_serial_number = signer.serial_number,
    };
}

pub const ExternalSignerOptions = struct {
    command: ExternalCommand,
    /// Borrowed for the signer's lifetime.
    certificate: Certificate,
    /// A directory this signer owns. Created if absent, and every file it
    /// holds belongs to one signing operation.
    scratch_path: []const u8,
    /// The image architecture, passed through as `MIZ_UKI_ARCHITECTURE`.
    architecture: []const u8,
    /// The environment the provider is started with, before the protocol's
    /// own variables are added over it.
    ///
    /// Forwarded whole, unlike a hook's, which gets a fixed environment
    /// containing nothing from the build machine. The difference is what the
    /// two things are: a hook is target code running inside the image, while a
    /// provider is the caller's own command whose entire job is to reach a
    /// signing service using the credentials of the machine that started the
    /// build. `miz sign` needs exactly that -- a GitHub OIDC request URL and
    /// token it exchanges for a short-lived signing token. A curated
    /// environment here would mean a signer that cannot sign.
    base_environment: BaseEnvironment = .{ .environ = .empty },
};

/// Where a caller's environment comes from. Two forms because a caller either
/// holds the process environment it was started with or has already built a
/// map to add its own conventions to, and converting between them to satisfy
/// this one call would be work with no purpose.
pub const BaseEnvironment = union(enum) {
    environ: std.process.Environ,
    /// Borrowed for the signer's lifetime.
    map: *const std.process.Environ.Map,
};

/// Signs by running a declared host command, and accumulates a record of each
/// operation for the caller to publish.
pub const ExternalSigner = struct {
    allocator: Allocator,
    io: Io,
    options: ExternalSignerOptions,
    index: usize = 0,
    records: std.array_list.Managed(SignatureRecord),
    /// The first provider identity seen. Every later one has to match it: an
    /// image whose UKIs were signed by two different services is not an image
    /// anyone can make a single statement about.
    identity: ?ProviderMetadata = null,
    failure: ?Error = null,
    /// The name the provider gave for its own failure, when it reported one in
    /// the form `miz sign` uses and that name is safe to repeat. A provider's
    /// output is otherwise dropped, so without this a caller can say only that
    /// signing failed, never what the signing service objected to.
    provider_error: ?[]u8 = null,

    pub fn init(
        allocator: Allocator,
        io: Io,
        options: ExternalSignerOptions,
    ) Error!ExternalSigner {
        // The scratch directory holds the unsigned image and the certificate
        // as plain files, so it is created private rather than made private
        // afterwards. A directory that already existed is narrowed instead,
        // because it may have been created by something less careful.
        const status = Dir.cwd().createDirPathStatus(
            io,
            options.scratch_path,
            .fromMode(0o700),
        ) catch return error.SigningWorkspaceFailed;
        if (status == .existed) {
            var directory = Dir.cwd().openDir(
                io,
                options.scratch_path,
                .{ .iterate = true },
            ) catch return error.SigningWorkspaceFailed;
            defer directory.close(io);
            directory.setPermissions(io, .fromMode(0o700)) catch
                return error.SigningWorkspaceFailed;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .records = std.array_list.Managed(SignatureRecord).init(allocator),
        };
    }

    pub fn deinit(self: *ExternalSigner) void {
        for (self.records.items) |record| freeRecord(self.allocator, record);
        self.records.deinit();
        if (self.identity) |identity| freeProviderMetadata(self.allocator, identity);
        if (self.provider_error) |name| self.allocator.free(name);
        self.* = undefined;
    }

    /// The records accumulated so far, owned by the signer.
    pub fn signatures(self: *const ExternalSigner) []const SignatureRecord {
        return self.records.items;
    }

    pub fn signer(self: *ExternalSigner) Signer {
        return .{ .context = self, .signFn = signThunk };
    }

    fn signThunk(
        context: ?*anyopaque,
        allocator: Allocator,
        request: SignRequest,
    ) Error![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(context.?));
        return self.signAlloc(allocator, request) catch |err| {
            self.failure = err;
            return err;
        };
    }

    fn signAlloc(
        self: *ExternalSigner,
        allocator: Allocator,
        request: SignRequest,
    ) Error![]u8 {
        const index = self.index;
        self.index += 1;

        var paths = try ScratchPaths.init(self.allocator, self.options.scratch_path, index);
        defer paths.deinit(self.allocator);
        paths.clear(self.io);
        defer paths.clear(self.io);

        Dir.cwd().writeFile(self.io, .{
            .sub_path = paths.unsigned,
            .data = request.unsigned,
            .flags = .{ .truncate = true, .permissions = .fromMode(0o600) },
        }) catch return error.SigningWorkspaceFailed;
        Dir.cwd().writeFile(self.io, .{
            .sub_path = paths.certificate,
            .data = self.options.certificate.pem,
            .flags = .{ .truncate = true, .permissions = .fromMode(0o600) },
        }) catch return error.SigningWorkspaceFailed;

        const unsigned_sha256 = artifact_pipeline.sha256Bytes(request.unsigned);
        try self.runProvider(paths, unsigned_sha256);

        const signed = Dir.cwd().readFileAlloc(
            self.io,
            paths.signed,
            allocator,
            .limited(request.unsigned.len + max_signature_overhead),
        ) catch return error.SigningProviderFailed;
        errdefer allocator.free(signed);

        const verification = try verifySigned(
            self.allocator,
            request.unsigned,
            signed,
            self.options.certificate,
        );
        const metadata = try self.readProviderMetadata(paths.metadata);
        errdefer if (metadata) |value| freeProviderMetadata(self.allocator, value);
        try self.requireStableIdentity(metadata);
        try self.appendRecord(request, signed, unsigned_sha256, verification, metadata);
        return signed;
    }

    fn runProvider(
        self: *ExternalSigner,
        paths: ScratchPaths,
        unsigned_sha256: Digest,
    ) Error!void {
        const command = self.options.command;
        var environment = switch (self.options.base_environment) {
            .environ => |environ| environ.createMap(self.allocator) catch
                return error.SigningProviderFailed,
            .map => |map| map.clone(self.allocator) catch
                return error.SigningProviderFailed,
        };
        defer environment.deinit();
        const unsigned_hex = artifact_pipeline.formatSha256(unsigned_sha256);
        const certificate_hex = artifact_pipeline.formatSha256(
            self.options.certificate.sha256,
        );
        environment.put("MIZ_UKI_UNSIGNED", paths.unsigned) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_SIGNED", paths.signed) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_CERTIFICATE", paths.certificate) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_SIGNING_METADATA", paths.metadata) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_ARCHITECTURE", self.options.architecture) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_UNSIGNED_SHA256", &unsigned_hex) catch return error.OutOfMemory;
        environment.put("MIZ_UKI_CERTIFICATE_SHA256", &certificate_hex) catch return error.OutOfMemory;

        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try argv.append(command.executable_path);
        if (command.argument) |argument| try argv.append(argument);

        // Neither stream is forwarded. A signing provider's output is the one
        // place a token or a signed blob could be echoed into a build log, and
        // a build log is the least controlled output this run has.
        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .environ_map = &environment,
            .stdout_limit = .limited(max_command_output_bytes),
            .stderr_limit = .limited(max_command_output_bytes),
            .timeout = .{ .duration = .{
                .raw = .fromSeconds(signing_command_timeout_seconds),
                .clock = .awake,
            } },
        }) catch return error.SigningProviderFailed;
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code == 0) return,
            else => {},
        }
        if (providerErrorName(result.stderr)) |name| {
            if (self.provider_error) |previous| self.allocator.free(previous);
            self.provider_error = try self.allocator.dupe(u8, name);
        }
        return error.SigningProviderFailed;
    }

    fn readProviderMetadata(
        self: *ExternalSigner,
        path: []const u8,
    ) Error!?ProviderMetadata {
        const bytes = Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(max_provider_metadata_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidSigningProviderMetadata,
        };
        defer self.allocator.free(bytes);

        const Wire = struct {
            schema: u32,
            provider: []const u8,
            endpoint: []const u8,
            account: []const u8,
            profile: []const u8,
            operation_id: []const u8,
            signing_certificate_sha256: []const u8,
            enrolled_certificate_sha256: []const u8,
        };
        const parsed = std.json.parseFromSlice(
            Wire,
            self.allocator,
            bytes,
            .{ .ignore_unknown_fields = false },
        ) catch return error.InvalidSigningProviderMetadata;
        defer parsed.deinit();
        const value = parsed.value;
        if (value.schema != 1) return error.InvalidSigningProviderMetadata;
        const signing_certificate_sha256 = artifact_pipeline.parseSha256(
            value.signing_certificate_sha256,
        ) catch return error.InvalidSigningProviderMetadata;
        const enrolled_certificate_sha256 = artifact_pipeline.parseSha256(
            value.enrolled_certificate_sha256,
        ) catch return error.InvalidSigningProviderMetadata;
        // The provider states which certificate is enrolled with the service
        // it used. Disagreeing with the declared one means the run signed with
        // something other than what it published, which no later check would
        // notice, because the signature itself is consistent either way.
        if (!std.mem.eql(
            u8,
            &enrolled_certificate_sha256,
            &self.options.certificate.sha256,
        )) {
            return error.InvalidSigningProviderMetadata;
        }
        return .{
            .provider = try self.allocator.dupe(u8, value.provider),
            .endpoint = try self.allocator.dupe(u8, value.endpoint),
            .account = try self.allocator.dupe(u8, value.account),
            .profile = try self.allocator.dupe(u8, value.profile),
            .operation_id = try self.allocator.dupe(u8, value.operation_id),
            .signing_certificate_sha256 = signing_certificate_sha256,
            .enrolled_certificate_sha256 = enrolled_certificate_sha256,
        };
    }

    fn requireStableIdentity(
        self: *ExternalSigner,
        metadata: ?ProviderMetadata,
    ) Error!void {
        const first = self.identity orelse {
            if (metadata) |value| {
                self.identity = try cloneProviderMetadata(self.allocator, value);
            }
            return;
        };
        const current = metadata orelse return error.SigningProviderIdentityChanged;
        if (!std.mem.eql(u8, first.provider, current.provider) or
            !std.mem.eql(u8, first.endpoint, current.endpoint) or
            !std.mem.eql(u8, first.account, current.account) or
            !std.mem.eql(u8, first.profile, current.profile))
        {
            return error.SigningProviderIdentityChanged;
        }
    }

    fn appendRecord(
        self: *ExternalSigner,
        request: SignRequest,
        signed: []const u8,
        unsigned_sha256: Digest,
        verification: Verification,
        metadata: ?ProviderMetadata,
    ) Error!void {
        const paths = try self.allocator.alloc([]const u8, request.esp_paths.len);
        var kept: usize = 0;
        errdefer {
            for (paths[0..kept]) |path| self.allocator.free(path);
            self.allocator.free(paths);
        }
        for (request.esp_paths, 0..) |path, index| {
            paths[index] = try self.allocator.dupe(u8, path);
            kept = index + 1;
        }
        const subject = try self.allocator.dupe(u8, verification.signer_subject_der);
        errdefer self.allocator.free(subject);
        const issuer = try self.allocator.dupe(u8, verification.signer_issuer_der);
        errdefer self.allocator.free(issuer);
        const serial = try self.allocator.dupe(u8, verification.signer_serial_number);
        errdefer self.allocator.free(serial);
        try self.records.append(.{
            .esp_paths = paths,
            .unsigned_sha256 = unsigned_sha256,
            .signed_sha256 = artifact_pipeline.sha256Bytes(signed),
            .signed_size = signed.len,
            .image_sha256 = verification.image_sha256,
            .certificate_sha256 = self.options.certificate.sha256,
            .signer_subject_der = subject,
            .signer_issuer_der = issuer,
            .signer_serial_number = serial,
            .provider = metadata,
        });
    }
};

const ScratchPaths = struct {
    unsigned: []const u8,
    signed: []const u8,
    certificate: []const u8,
    metadata: []const u8,

    fn init(allocator: Allocator, scratch_path: []const u8, index: usize) Error!ScratchPaths {
        const unsigned = try std.fmt.allocPrint(allocator, "{s}/unsigned-{d}.efi", .{ scratch_path, index });
        errdefer allocator.free(unsigned);
        const signed = try std.fmt.allocPrint(allocator, "{s}/signed-{d}.efi", .{ scratch_path, index });
        errdefer allocator.free(signed);
        const certificate = try std.fmt.allocPrint(allocator, "{s}/certificate-{d}.pem", .{ scratch_path, index });
        errdefer allocator.free(certificate);
        const metadata = try std.fmt.allocPrint(allocator, "{s}/metadata-{d}.json", .{ scratch_path, index });
        return .{
            .unsigned = unsigned,
            .signed = signed,
            .certificate = certificate,
            .metadata = metadata,
        };
    }

    /// Removes every file of this operation. Run before the provider as well
    /// as after it, so a signed image left behind by an earlier run can never
    /// be mistaken for this one's output.
    fn clear(self: ScratchPaths, io: Io) void {
        Dir.cwd().deleteFile(io, self.unsigned) catch {};
        Dir.cwd().deleteFile(io, self.signed) catch {};
        Dir.cwd().deleteFile(io, self.certificate) catch {};
        Dir.cwd().deleteFile(io, self.metadata) catch {};
    }

    fn deinit(self: *ScratchPaths, allocator: Allocator) void {
        allocator.free(self.unsigned);
        allocator.free(self.signed);
        allocator.free(self.certificate);
        allocator.free(self.metadata);
        self.* = undefined;
    }
};

fn cloneProviderMetadata(
    allocator: Allocator,
    value: ProviderMetadata,
) Allocator.Error!ProviderMetadata {
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

fn freeProviderMetadata(allocator: Allocator, value: ProviderMetadata) void {
    allocator.free(value.provider);
    allocator.free(value.endpoint);
    allocator.free(value.account);
    allocator.free(value.profile);
    allocator.free(value.operation_id);
}

fn freeRecord(allocator: Allocator, record: SignatureRecord) void {
    for (record.esp_paths) |path| allocator.free(path);
    allocator.free(record.esp_paths);
    allocator.free(record.signer_subject_der);
    allocator.free(record.signer_issuer_der);
    allocator.free(record.signer_serial_number);
    if (record.provider) |provider| freeProviderMetadata(allocator, provider);
}

/// The provider's own name for what went wrong, if it said so in the one form
/// that can be repeated safely.
///
/// A provider's stderr is not a place to take text from: it may hold a token,
/// a URL with one in it, or anything else the signing service returned. Only a
/// single line in the shape `miz sign` emits, whose remainder is a bare error
/// name, is accepted; anything longer, multi-line, or containing a character
/// an error name cannot have is dropped whole.
fn providerErrorName(stderr: []const u8) ?[]const u8 {
    const prefix = "miz sign: failed: ";
    var line = std.mem.trimEnd(u8, stderr, "\r\n");
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    line = line[prefix.len..];
    if (line.len == 0 or line.len > 128) return null;
    for (line) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '_')) return null;
    }
    return line;
}

test "only a safe provider error name is repeated" {
    try std.testing.expectEqualStrings(
        "ArtifactSigningSubmitFailed",
        providerErrorName("miz sign: failed: ArtifactSigningSubmitFailed\n").?,
    );
    try std.testing.expect(providerErrorName("secret output") == null);
    try std.testing.expect(providerErrorName("miz sign: failed: Bad\nInjected") == null);
    try std.testing.expect(providerErrorName("") == null);
}

test "a certificate is accepted in either form and normalized to both" {
    const allocator = std.testing.allocator;
    const der = testCertificateDer();
    const pem = try authenticode.encodePemCertificateAlloc(allocator, der);
    defer allocator.free(pem);

    var from_der = try loadCertificateAlloc(allocator, std.testing.io, .{ .inline_bytes = der });
    defer from_der.deinit(allocator);
    var from_pem = try loadCertificateAlloc(allocator, std.testing.io, .{ .inline_bytes = pem });
    defer from_pem.deinit(allocator);

    try std.testing.expectEqualSlices(u8, from_der.der, from_pem.der);
    try std.testing.expectEqualSlices(u8, from_der.pem, from_pem.pem);
    try std.testing.expectEqualSlices(u8, &from_der.sha256, &from_pem.sha256);
    try std.testing.expectError(
        error.InvalidSigningCertificate,
        loadCertificateAlloc(allocator, std.testing.io, .{ .inline_bytes = "not a certificate" }),
    );
    try std.testing.expectError(
        error.InvalidSigningCertificate,
        loadCertificateAlloc(allocator, std.testing.io, .{ .inline_bytes = "" }),
    );
}

test "verification accepts a signature over the image and rejects one over other bytes" {
    const allocator = std.testing.allocator;
    var certificate = try loadCertificateAlloc(
        allocator,
        std.testing.io,
        .{ .inline_bytes = testCertificateDer() },
    );
    defer certificate.deinit(allocator);

    const unsigned = try testUnsignedUki(allocator, "console=ttyS0");
    defer allocator.free(unsigned);
    const signed = try signForTest(allocator, unsigned, certificate.der);
    defer allocator.free(signed);

    const verification = try verifySigned(allocator, unsigned, signed, certificate);
    const expected = try authenticode.imageSha256(unsigned);
    try std.testing.expectEqualSlices(u8, &expected, &verification.image_sha256);

    // The signature of a different image, attached to this one. Every section
    // is intact and the signer is right; only the digest comparison objects.
    const other = try testUnsignedUki(allocator, "console=tty0");
    defer allocator.free(other);
    const other_signed = try signForTest(allocator, other, certificate.der);
    defer allocator.free(other_signed);
    const grafted = try graftCertificateTable(allocator, unsigned, other_signed);
    defer allocator.free(grafted);
    try std.testing.expectError(
        error.SignatureCoversOtherBytes,
        verifySigned(allocator, unsigned, grafted, certificate),
    );
}

test "verification rejects an unsigned result and a foreign signer" {
    const allocator = std.testing.allocator;
    var certificate = try loadCertificateAlloc(
        allocator,
        std.testing.io,
        .{ .inline_bytes = testCertificateDer() },
    );
    defer certificate.deinit(allocator);
    var other_certificate = try loadCertificateAlloc(
        allocator,
        std.testing.io,
        .{ .inline_bytes = testCertificateDerSerial(2) },
    );
    defer other_certificate.deinit(allocator);

    const unsigned = try testUnsignedUki(allocator, "console=ttyS0");
    defer allocator.free(unsigned);
    try std.testing.expectError(
        error.UnsignedResult,
        verifySigned(allocator, unsigned, unsigned, certificate),
    );

    const signed = try signForTest(allocator, unsigned, other_certificate.der);
    defer allocator.free(signed);
    try std.testing.expectError(
        error.SignerCertificateMismatch,
        verifySigned(allocator, unsigned, signed, certificate),
    );
}

test "verification rejects a result whose payload was rewritten" {
    const allocator = std.testing.allocator;
    var certificate = try loadCertificateAlloc(
        allocator,
        std.testing.io,
        .{ .inline_bytes = testCertificateDer() },
    );
    defer certificate.deinit(allocator);

    const unsigned = try testUnsignedUki(allocator, "console=ttyS0");
    defer allocator.free(unsigned);
    const other = try testUnsignedUki(allocator, "console=tty0");
    defer allocator.free(other);
    const signed = try signForTest(allocator, other, certificate.der);
    defer allocator.free(signed);
    try std.testing.expectError(
        error.SignedImageChanged,
        verifySigned(allocator, unsigned, signed, certificate),
    );
}

/// Signs the way a provider would, with a fixed signature in place of a key
/// operation. Nothing here verifies an RSA signature, so a constant is exactly
/// as good as a real one and needs no key to exist anywhere in the tree.
fn signForTest(
    allocator: Allocator,
    unsigned: []const u8,
    certificate_der: []const u8,
) ![]u8 {
    var prepared = try authenticode.prepareRsaSha256Alloc(allocator, unsigned);
    defer prepared.deinit(allocator);
    const signature = [_]u8{0x5a} ** 256;
    return authenticode.finishRsaSha256Alloc(
        allocator,
        prepared,
        certificate_der,
        &signature,
    );
}

/// Moves one image's certificate table onto another image, which is what a
/// provider that signed a stale file effectively returns.
fn graftCertificateTable(
    allocator: Allocator,
    unsigned: []const u8,
    signed_other: []const u8,
) ![]u8 {
    var inspection = try uki.inspect(allocator, signed_other);
    defer inspection.deinit(allocator);
    const directory = inspection.security_directory.?;
    const table = signed_other[directory.offset..][0..directory.size];

    const grafted = try allocator.alloc(u8, unsigned.len + table.len);
    errdefer allocator.free(grafted);
    @memcpy(grafted[0..unsigned.len], unsigned);
    @memcpy(grafted[unsigned.len..], table);
    // The security directory of a PE32+ image, at the fixed offset the UKI
    // writer uses for the images this test builds.
    const pe_offset = std.mem.readInt(u32, unsigned[0x3c..0x40], .little);
    const entry = pe_offset + 4 + 20 + 112 + 4 * 8;
    std.mem.writeInt(u32, grafted[entry..][0..4], @intCast(unsigned.len), .little);
    std.mem.writeInt(u32, grafted[entry + 4 ..][0..4], @intCast(table.len), .little);
    return grafted;
}

fn testUnsignedUki(allocator: Allocator, cmdline: []const u8) ![]u8 {
    const stub = try uki.syntheticStubPe(allocator, 0x8664);
    defer allocator.free(stub);
    return uki.generate(allocator, .{
        .stub = stub,
        .linux = "linux payload",
        .initrd = "initrd payload",
        .cmdline = cmdline,
        .os_release = "ID=miz\n",
        .uname = "6.8.12-test",
    });
}

fn testCertificateDer() []const u8 {
    return testCertificateDerSerial(1);
}

fn testCertificateDerSerial(serial: u8) []const u8 {
    return switch (serial) {
        2 => "\x30\x81\x92\x30\x7d\xa0\x03\x02\x01\x02\x02\x01\x02" ++
            "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" ++
            "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
            "Test Issuer" ++
            "\x30\x1e\x17\x0d\x32\x36\x30\x31\x30\x31\x30\x30\x30\x30" ++
            "\x30\x30\x5a\x17\x0d\x32\x37\x30\x31\x30\x31\x30\x30\x30" ++
            "\x30\x30\x30\x5a" ++
            "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
            "Test Signer" ++
            "\x30\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" ++
            "\x01\x05\x00\x03\x03\x00\x30\x00" ++
            "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05" ++
            "\x00\x03\x02\x00\x00",
        else => "\x30\x81\x92\x30\x7d\xa0\x03\x02\x01\x02\x02\x01\x01" ++
            "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" ++
            "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
            "Test Issuer" ++
            "\x30\x1e\x17\x0d\x32\x36\x30\x31\x30\x31\x30\x30\x30\x30" ++
            "\x30\x30\x5a\x17\x0d\x32\x37\x30\x31\x30\x31\x30\x30\x30" ++
            "\x30\x30\x30\x5a" ++
            "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
            "Test Signer" ++
            "\x30\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" ++
            "\x01\x05\x00\x03\x03\x00\x30\x00" ++
            "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05" ++
            "\x00\x03\x02\x00\x00",
    };
}

/// Writes an executable `/bin/sh` provider into `directory` and returns the
/// path to run it by, relative to the working directory the signer uses.
fn writeTestProvider(
    allocator: Allocator,
    tmp: *std.testing.TmpDir,
    name: []const u8,
    body: []const u8,
) ![]u8 {
    const script = try std.fmt.allocPrint(allocator, "#!/bin/sh\nset -e\n{s}", .{body});
    defer allocator.free(script);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = name,
        .data = script,
        .flags = .{ .truncate = true, .permissions = .fromMode(0o700) },
    });
    return std.fmt.allocPrint(
        allocator,
        "./.zig-cache/tmp/{s}/{s}",
        .{ tmp.sub_path, name },
    );
}

fn testScratchPath(allocator: Allocator, tmp: *const std.testing.TmpDir) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/scratch",
        .{tmp.sub_path},
    );
}

test "an external provider is run over the declared protocol and its result recorded" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var certificate = try loadCertificateAlloc(
        allocator,
        io,
        .{ .inline_bytes = testCertificateDer() },
    );
    defer certificate.deinit(allocator);

    const unsigned = try testUnsignedUki(allocator, "console=ttyS0");
    defer allocator.free(unsigned);
    const expected_signed = try signForTest(allocator, unsigned, certificate.der);
    defer allocator.free(expected_signed);
    try tmp.dir.writeFile(io, .{
        .sub_path = "presigned.efi",
        .data = expected_signed,
        .flags = .{ .truncate = true },
    });

    // The provider records the environment it was handed before producing a
    // result, so the test can check the protocol rather than assume it.
    const tmp_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(tmp_path);
    const body = try std.fmt.allocPrint(allocator,
        \\{{
        \\  echo "unsigned=$MIZ_UKI_UNSIGNED"
        \\  echo "signed=$MIZ_UKI_SIGNED"
        \\  echo "unsigned_sha256=$MIZ_UKI_UNSIGNED_SHA256"
        \\  echo "certificate_sha256=$MIZ_UKI_CERTIFICATE_SHA256"
        \\  echo "architecture=$MIZ_UKI_ARCHITECTURE"
        \\  echo "marker=$MIZ_TEST_MARKER"
        \\  cat "$MIZ_UKI_CERTIFICATE"
        \\}} > "{s}/observed.txt"
        \\test -s "$MIZ_UKI_UNSIGNED"
        \\cp "{s}/presigned.efi" "$MIZ_UKI_SIGNED"
        \\
    , .{ tmp_path, tmp_path });
    defer allocator.free(body);
    const provider_path = try writeTestProvider(allocator, &tmp, "provider.sh", body);
    defer allocator.free(provider_path);
    const scratch_path = try testScratchPath(allocator, &tmp);
    defer allocator.free(scratch_path);

    // The caller's own environment is forwarded whole, because a real provider
    // reaches a signing service with the build machine's credentials. Built by
    // hand rather than taken from this process so the test says what arrives.
    const posix_environ = comptime std.process.Environ.Block == std.process.Environ.PosixBlock;
    const forwarded = [_:null]?[*:0]const u8{"MIZ_TEST_MARKER=forwarded"};
    const environ: std.process.Environ = if (posix_environ)
        .{ .block = .{ .slice = &forwarded } }
    else
        .empty;

    var signer = try ExternalSigner.init(allocator, io, .{
        .command = .{ .executable_path = provider_path },
        .certificate = certificate,
        .scratch_path = scratch_path,
        .architecture = "x86_64",
        .base_environment = .{ .environ = environ },
    });
    defer signer.deinit();

    const paths = [_][]const u8{ "EFI/Linux/miz.efi", "EFI/BOOT/BOOTX64.EFI" };
    const signed = try signer.signer().sign(allocator, .{
        .esp_paths = &paths,
        .unsigned = unsigned,
    });
    defer allocator.free(signed);
    try std.testing.expectEqualSlices(u8, expected_signed, signed);

    const observed = try tmp.dir.readFileAlloc(io, "observed.txt", allocator, .limited(64 * 1024));
    defer allocator.free(observed);
    const unsigned_hex = artifact_pipeline.formatSha256(
        artifact_pipeline.sha256Bytes(unsigned),
    );
    const certificate_hex = artifact_pipeline.formatSha256(certificate.sha256);

    // The digests are handed over as text so the provider can refuse a file it
    // was not asked to sign. If they did not match the file, that check would
    // be checking nothing.
    try std.testing.expect(std.mem.indexOf(u8, observed, &unsigned_hex) != null);
    try std.testing.expect(std.mem.indexOf(u8, observed, &certificate_hex) != null);
    try std.testing.expect(std.mem.indexOf(u8, observed, "architecture=x86_64") != null);
    if (posix_environ) {
        try std.testing.expect(std.mem.indexOf(u8, observed, "marker=forwarded") != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, observed, certificate.pem) != null);

    // Scratch files are the unsigned image and the certificate in the clear,
    // so they do not outlive the operation that needed them.
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.readFileAlloc(io, "scratch/unsigned-0.efi", allocator, .limited(64)),
    );

    const records = signer.signatures();
    try std.testing.expectEqual(@as(usize, 1), records.len);
    const record = records[0];
    try std.testing.expectEqual(@as(usize, 2), record.esp_paths.len);
    try std.testing.expectEqualStrings("EFI/Linux/miz.efi", record.esp_paths[0]);
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTX64.EFI", record.esp_paths[1]);
    try std.testing.expectEqual(signed.len, record.signed_size);
    try std.testing.expectEqualSlices(
        u8,
        &artifact_pipeline.sha256Bytes(unsigned),
        &record.unsigned_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &artifact_pipeline.sha256Bytes(signed),
        &record.signed_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &(try authenticode.imageSha256(unsigned)),
        &record.image_sha256,
    );
    try std.testing.expectEqualSlices(u8, &certificate.sha256, &record.certificate_sha256);
    // No metadata file was written, which is a provider with no service
    // identity to state rather than a failure.
    try std.testing.expect(record.provider == null);
}

test "a provider that fails or returns the wrong bytes is not taken at its word" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Case = struct {
        name: []const u8,
        body: []const u8,
        expected: Error,
        reported: ?[]const u8 = null,
    };
    const cases = [_]Case{
        // Nothing about a non-zero exit says which UKI is now unsigned, so the
        // only safe reading is that the image cannot be built.
        .{ .name = "failing.sh", .body = "exit 3\n", .expected = error.SigningProviderFailed },
        .{ .name = "silent.sh", .body = "exit 0\n", .expected = error.SigningProviderFailed },
        // A provider that named its failure the way `miz sign` does gets that
        // name repeated, so an operator is told what the signing service
        // objected to rather than only that signing stopped.
        .{
            .name = "named.sh",
            .body = "echo 'miz sign: failed: ArtifactSigningSubmitFailed' >&2\nexit 1\n",
            .expected = error.SigningProviderFailed,
            .reported = "ArtifactSigningSubmitFailed",
        },
        // Whatever else it printed is dropped: stderr is where a token would
        // appear, and a build log is the least controlled output a run has.
        .{
            .name = "chatty.sh",
            .body = "echo 'token=s3cret' >&2\nexit 1\n",
            .expected = error.SigningProviderFailed,
        },
        // A provider that copied its input and exited zero looks successful.
        // Only checking the result for a signature notices.
        .{
            .name = "passthrough.sh",
            .body = "cp \"$MIZ_UKI_UNSIGNED\" \"$MIZ_UKI_SIGNED\"\n",
            .expected = error.UnsignedResult,
        },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var certificate = try loadCertificateAlloc(
            allocator,
            io,
            .{ .inline_bytes = testCertificateDer() },
        );
        defer certificate.deinit(allocator);
        const unsigned = try testUnsignedUki(allocator, "console=ttyS0");
        defer allocator.free(unsigned);

        const provider_path = try writeTestProvider(allocator, &tmp, case.name, case.body);
        defer allocator.free(provider_path);
        const scratch_path = try testScratchPath(allocator, &tmp);
        defer allocator.free(scratch_path);

        var signer = try ExternalSigner.init(allocator, io, .{
            .command = .{ .executable_path = provider_path },
            .certificate = certificate,
            .scratch_path = scratch_path,
            .architecture = "x86_64",
        });
        defer signer.deinit();

        const paths = [_][]const u8{"EFI/Linux/miz.efi"};
        try std.testing.expectError(case.expected, signer.signer().sign(allocator, .{
            .esp_paths = &paths,
            .unsigned = unsigned,
        }));
        // The failure is kept so the run can report which step refused rather
        // than only that the build stopped.
        try std.testing.expectEqual(case.expected, signer.failure.?);
        try std.testing.expectEqual(@as(usize, 0), signer.signatures().len);
        if (case.reported) |name| {
            try std.testing.expectEqualStrings(name, signer.provider_error.?);
        } else {
            try std.testing.expect(signer.provider_error == null);
        }
    }
}
