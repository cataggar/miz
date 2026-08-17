//! `vmiz sign` implements the external UKI signer protocol used by the
//! Azure Linux release builder. The private key remains in Azure Artifact
//! Signing; this command exchanges GitHub OIDC for a short-lived token and
//! submits only the Authenticode signed-attributes digest.

const std = @import("std");
const vmiz = @import("vmiz");
const atomic_output = @import("../atomic_output.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Environ = std.process.Environ;
const Io = std.Io;

const max_unsigned_bytes = 512 * 1024 * 1024;
const max_certificate_bytes = 1024 * 1024;
const max_response_bytes = 1024 * 1024;
const artifact_signing_api_version = "2024-06-15";
const artifact_signing_scope = "https://codesigning.azure.net/.default";
const artifact_signing_provider = "azure-artifact-signing";
const github_actions_host_suffix = ".actions.githubusercontent.com";
const oidc_audience = "api%3A%2F%2FAzureADTokenExchange";
const decodePemCertificateAlloc =
    vmiz.authenticode.decodePemCertificateAlloc;
const encodePemCertificateAlloc =
    vmiz.authenticode.encodePemCertificateAlloc;

const OidcResponse = struct {
    value: []const u8,
};

const TokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
};

const TokenHttpRequest = enum {
    github_oidc,
    azure_token_exchange,
};

pub fn run(
    allocator: Allocator,
    io: Io,
    environ: Environ,
    args: []const []const u8,
) u8 {
    const result = if (args.len == 0)
        runFallible(allocator, io, environ)
    else if (args.len == 2 and std.mem.eql(u8, args[0], "certificate"))
        exportCertificateFallible(allocator, io, environ, args[1])
    else {
        std.debug.print(
            "usage: vmiz sign [certificate <absolute-output.pem>]\n",
            .{},
        );
        return 1;
    };
    result catch |err| {
        std.debug.print("vmiz sign: failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn runFallible(allocator: Allocator, io: Io, environ: Environ) !void {
    const unsigned_path = try requiredEnvAlloc(
        allocator,
        environ,
        "VMIZ_UKI_UNSIGNED",
    );
    defer allocator.free(unsigned_path);
    const signed_path = try requiredEnvAlloc(
        allocator,
        environ,
        "VMIZ_UKI_SIGNED",
    );
    defer allocator.free(signed_path);
    const certificate_path = try requiredEnvAlloc(
        allocator,
        environ,
        "VMIZ_UKI_CERTIFICATE",
    );
    defer allocator.free(certificate_path);
    const expected_unsigned_text = try requiredEnvAlloc(
        allocator,
        environ,
        "VMIZ_UKI_UNSIGNED_SHA256",
    );
    defer allocator.free(expected_unsigned_text);
    const expected_certificate_text = try requiredEnvAlloc(
        allocator,
        environ,
        "VMIZ_UKI_CERTIFICATE_SHA256",
    );
    defer allocator.free(expected_certificate_text);
    var provider = try ArtifactSigningEnvironment.init(
        allocator,
        environ,
    );
    defer provider.deinit(allocator);

    const unsigned = try Dir.cwd().readFileAlloc(
        io,
        unsigned_path,
        allocator,
        .limited(max_unsigned_bytes),
    );
    defer allocator.free(unsigned);
    const expected_unsigned = try vmiz.artifact_pipeline.parseSha256(
        expected_unsigned_text,
    );
    const actual_unsigned = vmiz.artifact_pipeline.sha256Bytes(unsigned);
    if (!std.mem.eql(u8, &actual_unsigned, &expected_unsigned))
        return error.UnsignedUkiDigestMismatch;

    const certificate_pem = try Dir.cwd().readFileAlloc(
        io,
        certificate_path,
        allocator,
        .limited(max_certificate_bytes),
    );
    defer allocator.free(certificate_pem);
    const certificate_der = try decodePemCertificateAlloc(
        allocator,
        certificate_pem,
    );
    defer allocator.free(certificate_der);
    const expected_certificate = try vmiz.artifact_pipeline.parseSha256(
        expected_certificate_text,
    );
    const actual_certificate = vmiz.artifact_pipeline.sha256Bytes(
        certificate_der,
    );
    if (!std.mem.eql(u8, &actual_certificate, &expected_certificate))
        return error.SigningCertificateFingerprintMismatch;

    var prepared = try vmiz.authenticode.prepareRsaSha256Alloc(
        allocator,
        unsigned,
    );
    defer prepared.deinit(allocator);

    var http_client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http_client.deinit();
    const access_token = try acquireAzureAccessTokenAlloc(
        allocator,
        &http_client,
        provider.oidc_request_url,
        provider.oidc_request_token,
        provider.tenant_id,
        provider.client_id,
    );
    defer allocator.free(access_token);
    var signing_result = try signDigestWithArtifactSigningAlloc(
        io,
        allocator,
        &http_client,
        provider.config(),
        access_token,
        prepared.signing_digest,
        .{},
    );
    defer signing_result.deinit(allocator);

    var certificate_chain = try vmiz.authenticode
        .parseArtifactSigningCertificateChainAlloc(
        allocator,
        signing_result.certificate_bundle,
    );
    defer certificate_chain.deinit(allocator);
    const signing_certificate = try vmiz.authenticode
        .artifactSigningCertificateDer(signing_result.certificate_bundle);
    if (!std.mem.eql(u8, signing_certificate, certificate_der))
        return error.ArtifactSigningCertificateMismatch;

    const signed = try vmiz.authenticode.finishRsaSha256WithChainAlloc(
        allocator,
        prepared,
        signing_certificate,
        certificate_chain.certificates,
        signing_result.signature,
    );
    defer allocator.free(signed);
    try atomic_output.writeAtomic(io, allocator, signed_path, signed);

    const metadata_path_optional = environ.getAlloc(
        allocator,
        "VMIZ_UKI_SIGNING_METADATA",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
    if (metadata_path_optional) |metadata_path| {
        defer allocator.free(metadata_path);
        if (metadata_path.len == 0 or !Dir.path.isAbsolute(metadata_path))
            return error.SigningMetadataPathMustBeAbsolute;
        const leaf_sha256 = vmiz.artifact_pipeline.sha256Bytes(
            signing_certificate,
        );
        const leaf_sha256_hex = vmiz.artifact_pipeline.formatSha256(leaf_sha256);
        const enrolled_certificate_sha256_hex = vmiz.artifact_pipeline.formatSha256(
            actual_certificate,
        );
        const metadata = try std.json.Stringify.valueAlloc(
            allocator,
            .{
                .schema = @as(u32, 1),
                .provider = artifact_signing_provider,
                .endpoint = provider.endpoint,
                .account = provider.account,
                .profile = provider.profile,
                .operation_id = signing_result.operation_id,
                .signing_certificate_sha256 = &leaf_sha256_hex,
                .enrolled_certificate_sha256 = &enrolled_certificate_sha256_hex,
            },
            .{ .whitespace = .indent_2 },
        );
        defer allocator.free(metadata);
        try atomic_output.writeAtomic(io, allocator, metadata_path, metadata);
    }
}

fn exportCertificateFallible(
    allocator: Allocator,
    io: Io,
    environ: Environ,
    output_path: []const u8,
) !void {
    if (!Dir.path.isAbsolute(output_path))
        return error.SigningCertificatePathMustBeAbsolute;
    var provider = try ArtifactSigningEnvironment.init(allocator, environ);
    defer provider.deinit(allocator);
    var http_client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http_client.deinit();
    const access_token = try acquireAzureAccessTokenAlloc(
        allocator,
        &http_client,
        provider.oidc_request_url,
        provider.oidc_request_token,
        provider.tenant_id,
        provider.client_id,
    );
    defer allocator.free(access_token);
    const certificate_der = try fetchSigningCertificateAlloc(
        allocator,
        &http_client,
        provider.config(),
        access_token,
    );
    defer allocator.free(certificate_der);
    const certificate_pem = try encodePemCertificateAlloc(
        allocator,
        certificate_der,
    );
    defer allocator.free(certificate_pem);
    try atomic_output.writeAtomic(io, allocator, output_path, certificate_pem);
}

fn requiredEnvAlloc(
    allocator: Allocator,
    environ: Environ,
    name: []const u8,
) ![]u8 {
    const value = try environ.getAlloc(allocator, name);
    errdefer allocator.free(value);
    if (value.len == 0) return error.EmptyEnvironmentVariable;
    return value;
}

fn acquireAzureAccessTokenAlloc(
    allocator: Allocator,
    client: *std.http.Client,
    oidc_request_url: []const u8,
    oidc_request_token: []const u8,
    tenant_id: []const u8,
    client_id: []const u8,
) ![]u8 {
    const audience_url = try appendOidcAudienceAlloc(
        allocator,
        oidc_request_url,
    );
    defer allocator.free(audience_url);
    const oidc_authorization = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{oidc_request_token},
    );
    defer allocator.free(oidc_authorization);
    const oidc_body = try fetchBoundedAlloc(
        allocator,
        client,
        .github_oidc,
        .GET,
        audience_url,
        null,
        &.{
            .{ .name = "Accept", .value = "application/json" },
            .{ .name = "Authorization", .value = oidc_authorization },
        },
    );
    defer allocator.free(oidc_body);
    const oidc = try std.json.parseFromSlice(
        OidcResponse,
        allocator,
        oidc_body,
        .{ .ignore_unknown_fields = true },
    );
    defer oidc.deinit();
    if (oidc.value.value.len == 0) return error.EmptyGithubOidcToken;

    const token_url = try std.fmt.allocPrint(
        allocator,
        "https://login.microsoftonline.com/{s}/oauth2/v2.0/token",
        .{tenant_id},
    );
    defer allocator.free(token_url);
    const token_form = try formEncodeAlloc(allocator, &.{
        .{ "client_id", client_id },
        .{ "scope", artifact_signing_scope },
        .{
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        },
        .{ "client_assertion", oidc.value.value },
        .{ "grant_type", "client_credentials" },
    });
    defer allocator.free(token_form);
    const token_body = try fetchBoundedAlloc(
        allocator,
        client,
        .azure_token_exchange,
        .POST,
        token_url,
        token_form,
        &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }},
    );
    defer allocator.free(token_body);
    const token = try std.json.parseFromSlice(
        TokenResponse,
        allocator,
        token_body,
        .{ .ignore_unknown_fields = true },
    );
    defer token.deinit();
    if (!std.ascii.eqlIgnoreCase(token.value.token_type, "Bearer") or
        token.value.access_token.len == 0)
    {
        return error.InvalidAzureAccessToken;
    }
    return allocator.dupe(u8, token.value.access_token);
}

const ArtifactSigningConfig = struct {
    endpoint: []const u8,
    account: []const u8,
    profile: []const u8,
};

const ArtifactSigningEnvironment = struct {
    tenant_id: []u8,
    client_id: []u8,
    endpoint: []u8,
    account: []u8,
    profile: []u8,
    oidc_request_url: []u8,
    oidc_request_token: []u8,

    fn init(allocator: Allocator, environ: Environ) !ArtifactSigningEnvironment {
        const tenant_id = try requiredEnvAlloc(
            allocator,
            environ,
            "VMIZ_AZURE_TENANT_ID",
        );
        errdefer allocator.free(tenant_id);
        const client_id = try requiredEnvAlloc(
            allocator,
            environ,
            "VMIZ_AZURE_CLIENT_ID",
        );
        errdefer allocator.free(client_id);
        const endpoint_env = try requiredEnvAlloc(
            allocator,
            environ,
            "VMIZ_ARTIFACT_SIGNING_ENDPOINT",
        );
        defer allocator.free(endpoint_env);
        const endpoint = try normalizeArtifactSigningEndpointAlloc(
            allocator,
            endpoint_env,
        );
        errdefer allocator.free(endpoint);
        const account = try requiredEnvAlloc(
            allocator,
            environ,
            "VMIZ_ARTIFACT_SIGNING_ACCOUNT",
        );
        errdefer allocator.free(account);
        const profile = try requiredEnvAlloc(
            allocator,
            environ,
            "VMIZ_ARTIFACT_SIGNING_PROFILE",
        );
        errdefer allocator.free(profile);
        const oidc_request_url = try requiredEnvAlloc(
            allocator,
            environ,
            "ACTIONS_ID_TOKEN_REQUEST_URL",
        );
        errdefer allocator.free(oidc_request_url);
        const oidc_request_token = try requiredEnvAlloc(
            allocator,
            environ,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        );
        errdefer allocator.free(oidc_request_token);

        if (!isUuid(tenant_id) or !isUuid(client_id))
            return error.InvalidAzureIdentity;
        try validatePathSegment(account);
        try validatePathSegment(profile);
        try validateOidcRequestUrl(oidc_request_url);
        return .{
            .tenant_id = tenant_id,
            .client_id = client_id,
            .endpoint = endpoint,
            .account = account,
            .profile = profile,
            .oidc_request_url = oidc_request_url,
            .oidc_request_token = oidc_request_token,
        };
    }

    fn deinit(self: *ArtifactSigningEnvironment, allocator: Allocator) void {
        allocator.free(self.tenant_id);
        allocator.free(self.client_id);
        allocator.free(self.endpoint);
        allocator.free(self.account);
        allocator.free(self.profile);
        allocator.free(self.oidc_request_url);
        allocator.free(self.oidc_request_token);
        self.* = undefined;
    }

    fn config(self: ArtifactSigningEnvironment) ArtifactSigningConfig {
        return .{
            .endpoint = self.endpoint,
            .account = self.account,
            .profile = self.profile,
        };
    }
};

const ArtifactSigningPollOptions = struct {
    max_attempts: usize = 60,
    sleep: bool = true,
};

const ArtifactSigningResult = struct {
    signature: []u8,
    certificate_bundle: []u8,
    operation_id: []u8,

    fn deinit(self: *ArtifactSigningResult, allocator: Allocator) void {
        allocator.free(self.signature);
        allocator.free(self.certificate_bundle);
        allocator.free(self.operation_id);
        self.* = undefined;
    }
};

const ArtifactOperation = struct {
    id: []const u8,
    status: []const u8,
    result: ?struct {
        signature: ?[]const u8 = null,
        signingCertificate: ?[]const u8 = null,
    } = null,
    @"error": ?struct {
        code: ?[]const u8 = null,
        message: ?[]const u8 = null,
    } = null,
};

const ArtifactHttpResponse = struct {
    status: std.http.Status,
    body: []u8,
    operation_location: ?[]u8,
    retry_after_seconds: ?u32,

    fn deinit(self: *ArtifactHttpResponse, allocator: Allocator) void {
        allocator.free(self.body);
        if (self.operation_location) |value| allocator.free(value);
        self.* = undefined;
    }
};

fn signDigestWithArtifactSigningAlloc(
    io: Io,
    allocator: Allocator,
    client: *std.http.Client,
    config: ArtifactSigningConfig,
    access_token: []const u8,
    digest: [32]u8,
    poll_options: ArtifactSigningPollOptions,
) !ArtifactSigningResult {
    if (poll_options.max_attempts == 0)
        return error.InvalidArtifactSigningPollConfiguration;

    var digest_text_buffer: [
        std.base64.standard.Encoder.calcSize(digest.len)
    ]u8 = undefined;
    const digest_text = std.base64.standard.Encoder.encode(
        &digest_text_buffer,
        &digest,
    );
    const request_body = try std.json.Stringify.valueAlloc(
        allocator,
        .{
            .signatureAlgorithm = "RS256",
            .digest = digest_text,
        },
        .{},
    );
    defer allocator.free(request_body);
    const submit_url = try artifactSigningUrlAlloc(
        allocator,
        config,
        ":sign",
    );
    defer allocator.free(submit_url);
    var submit = try artifactRequestAlloc(
        allocator,
        client,
        .POST,
        submit_url,
        access_token,
        "application/json",
        request_body,
    );
    defer submit.deinit(allocator);
    if (submit.status != .accepted)
        return error.ArtifactSigningSubmitFailed;
    const operation_location = submit.operation_location orelse
        return error.ArtifactSigningOperationLocationMissing;
    const operation_id = try validateArtifactSigningOperationLocation(
        allocator,
        config,
        operation_location,
    );

    var attempt: usize = 0;
    var delay_seconds: u32 = 1;
    while (attempt < poll_options.max_attempts) : (attempt += 1) {
        var response = try artifactRequestAlloc(
            allocator,
            client,
            .GET,
            operation_location,
            access_token,
            "application/json",
            null,
        );
        defer response.deinit(allocator);

        if (response.status == .request_timeout or
            response.status == .too_many_requests or
            response.status.class() == .server_error)
        {
            if (attempt + 1 == poll_options.max_attempts)
                return error.ArtifactSigningTimedOut;
            if (poll_options.sleep) {
                const retry_after = response.retry_after_seconds orelse
                    delay_seconds;
                try Io.sleep(io, .fromSeconds(@min(retry_after, 30)), .awake);
            }
            delay_seconds = @min(delay_seconds * 2, 5);
            continue;
        }
        if (response.status != .ok)
            return error.ArtifactSigningPollFailed;

        const operation = try parseArtifactOperation(
            allocator,
            response.body,
        );
        defer operation.deinit();
        if (!std.mem.eql(u8, operation.value.id, operation_id))
            return error.ArtifactSigningOperationIdMismatch;
        if (std.mem.eql(u8, operation.value.status, "Succeeded")) {
            const result = operation.value.result orelse
                return error.ArtifactSigningResultMissing;
            const signature_text = result.signature orelse
                return error.ArtifactSigningResultMissing;
            const certificate_text = result.signingCertificate orelse
                return error.ArtifactSigningResultMissing;
            const signature = try decodeStandardBase64Alloc(
                allocator,
                signature_text,
                max_certificate_bytes,
            );
            errdefer allocator.free(signature);
            if (signature.len != 128 and signature.len != 256 and
                signature.len != 384 and signature.len != 512)
            {
                return error.InvalidRsaSignatureSize;
            }
            const encoded_certificate_bundle = try decodeStandardBase64Alloc(
                allocator,
                certificate_text,
                max_certificate_bytes,
            );
            defer allocator.free(encoded_certificate_bundle);
            const certificate_bundle = try decodeMimeBase64Alloc(
                allocator,
                encoded_certificate_bundle,
                max_certificate_bytes,
            );
            errdefer allocator.free(certificate_bundle);
            return .{
                .signature = signature,
                .certificate_bundle = certificate_bundle,
                .operation_id = try allocator.dupe(u8, operation_id),
            };
        }
        if (std.mem.eql(u8, operation.value.status, "Failed"))
            return error.ArtifactSigningOperationFailed;
        if (std.mem.eql(u8, operation.value.status, "Canceled"))
            return error.ArtifactSigningOperationCanceled;
        if (!std.mem.eql(u8, operation.value.status, "NotStarted") and
            !std.mem.eql(u8, operation.value.status, "Running") and
            !std.mem.eql(u8, operation.value.status, "InProgress"))
        {
            reportUnknownArtifactSigningOperationStatus(
                operation.value.status,
            );
            return error.InvalidArtifactSigningOperationStatus;
        }
        if (attempt + 1 == poll_options.max_attempts)
            return error.ArtifactSigningTimedOut;
        if (poll_options.sleep) {
            const retry_after = response.retry_after_seconds orelse
                delay_seconds;
            try Io.sleep(io, .fromSeconds(@min(retry_after, 30)), .awake);
        }
        delay_seconds = @min(delay_seconds * 2, 5);
    }
    return error.ArtifactSigningTimedOut;
}

fn reportUnknownArtifactSigningOperationStatus(status: []const u8) void {
    if (status.len == 0 or status.len > 64) {
        std.debug.print(
            "vmiz sign: Artifact Signing returned a redacted operation status\n",
            .{},
        );
        return;
    }
    for (status) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and
            byte != '_' and byte != '.')
        {
            std.debug.print(
                "vmiz sign: Artifact Signing returned a redacted operation status\n",
                .{},
            );
            return;
        }
    }
    std.debug.print(
        "vmiz sign: Artifact Signing returned operation status: {s}\n",
        .{status},
    );
}

fn fetchSigningCertificateAlloc(
    allocator: Allocator,
    client: *std.http.Client,
    config: ArtifactSigningConfig,
    access_token: []const u8,
) ![]u8 {
    const url = try artifactSigningUrlAlloc(
        allocator,
        config,
        "/sign/certchain",
    );
    defer allocator.free(url);
    var response = try artifactRequestAlloc(
        allocator,
        client,
        .GET,
        url,
        access_token,
        "application/x-x509-ca-cert",
        null,
    );
    defer response.deinit(allocator);
    if (response.status != .ok)
        return error.ArtifactSigningCertificateFetchFailed;
    try vmiz.authenticode.validateX509CertificateDer(response.body);
    return allocator.dupe(u8, response.body);
}

fn artifactRequestAlloc(
    allocator: Allocator,
    client: *std.http.Client,
    method: std.http.Method,
    url: []const u8,
    access_token: []const u8,
    accept: []const u8,
    payload: ?[]u8,
) !ArtifactHttpResponse {
    const authorization = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{access_token},
    );
    defer allocator.free(authorization);
    const uri = try std.Uri.parse(url);
    const extra_headers = [_]std.http.Header{
        .{ .name = "Accept", .value = accept },
        .{ .name = "client-version", .value = "vmiz/1" },
        .{ .name = "Authorization", .value = authorization },
    };
    // Zig 0.16 does not emit privileged_headers on the initial request.
    // Redirects are forbidden, so Authorization cannot cross origins here.
    var request = try client.request(method, uri, .{
        .redirect_behavior = .not_allowed,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
            .content_type = if (payload != null)
                .{ .override = "application/json" }
            else
                .default,
        },
        .extra_headers = &extra_headers,
    });
    defer request.deinit();
    if (payload) |body| {
        try request.sendBodyComplete(body);
    } else {
        try request.sendBodiless();
    }
    var response = try request.receiveHead(&.{});

    var operation_location: ?[]u8 = null;
    errdefer if (operation_location) |value| allocator.free(value);
    var retry_after_seconds: ?u32 = null;
    var headers = response.head.iterateHeaders();
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Operation-Location")) {
            if (operation_location != null)
                return error.DuplicateArtifactSigningOperationLocation;
            operation_location = try allocator.dupe(u8, header.value);
        } else if (std.ascii.eqlIgnoreCase(header.name, "Retry-After")) {
            if (retry_after_seconds != null)
                return error.DuplicateArtifactSigningRetryAfter;
            retry_after_seconds = std.fmt.parseInt(
                u32,
                header.value,
                10,
            ) catch return error.InvalidArtifactSigningRetryAfter;
        }
    }
    if (response.head.content_encoding != .identity)
        return error.UnexpectedArtifactSigningContentEncoding;
    var transfer_buffer: [8192]u8 = undefined;
    const body = try response.reader(&transfer_buffer).allocRemaining(
        allocator,
        .limited(max_response_bytes),
    );
    return .{
        .status = response.head.status,
        .body = body,
        .operation_location = operation_location,
        .retry_after_seconds = retry_after_seconds,
    };
}

fn parseArtifactOperation(
    allocator: Allocator,
    body: []const u8,
) !std.json.Parsed(ArtifactOperation) {
    return std.json.parseFromSlice(
        ArtifactOperation,
        allocator,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            const value = std.json.parseFromSlice(
                std.json.Value,
                allocator,
                body,
                .{},
            ) catch |syntax_err| switch (syntax_err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidArtifactSigningOperationJson,
            };
            defer value.deinit();
            return error.InvalidArtifactSigningOperationSchema;
        },
    };
}

fn artifactSigningUrlAlloc(
    allocator: Allocator,
    config: ArtifactSigningConfig,
    suffix: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/codesigningaccounts/{s}/certificateprofiles/{s}{s}?api-version={s}",
        .{
            config.endpoint,
            config.account,
            config.profile,
            suffix,
            artifact_signing_api_version,
        },
    );
}

fn expectedArtifactSigningPollUrlAlloc(
    allocator: Allocator,
    config: ArtifactSigningConfig,
    operation_id: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/codesigningaccounts/{s}/certificateprofiles/{s}/sign/{s}?api-version={s}",
        .{
            config.endpoint,
            config.account,
            config.profile,
            operation_id,
            artifact_signing_api_version,
        },
    );
}

fn validateArtifactSigningOperationLocation(
    allocator: Allocator,
    config: ArtifactSigningConfig,
    operation_location: []const u8,
) ![]const u8 {
    const marker = "/sign/";
    const id_start = (std.mem.lastIndexOf(
        u8,
        operation_location,
        marker,
    ) orelse return error.InvalidArtifactSigningOperationLocation) + marker.len;
    const id_end = std.mem.indexOfScalarPos(
        u8,
        operation_location,
        id_start,
        '?',
    ) orelse return error.InvalidArtifactSigningOperationLocation;
    const operation_id = operation_location[id_start..id_end];
    if (!isUuid(operation_id))
        return error.InvalidArtifactSigningOperationId;
    const expected = try expectedArtifactSigningPollUrlAlloc(
        allocator,
        config,
        operation_id,
    );
    defer allocator.free(expected);
    if (!std.mem.eql(u8, expected, operation_location))
        return error.InvalidArtifactSigningOperationLocation;
    return operation_id;
}

fn decodeStandardBase64Alloc(
    allocator: Allocator,
    encoded: []const u8,
    max_size: usize,
) ![]u8 {
    if (encoded.len == 0) return error.EmptyBase64Value;
    const decoded_size = try std.base64.standard.Decoder.calcSizeForSlice(
        encoded,
    );
    if (decoded_size == 0 or decoded_size > max_size)
        return error.InvalidBase64ValueSize;
    const decoded = try allocator.alloc(u8, decoded_size);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    return decoded;
}

fn decodeMimeBase64Alloc(
    allocator: Allocator,
    encoded: []const u8,
    max_size: usize,
) ![]u8 {
    var compact: std.Io.Writer.Allocating = .init(allocator);
    defer compact.deinit();
    for (encoded) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        try compact.writer.writeByte(byte);
    }
    return decodeStandardBase64Alloc(allocator, compact.written(), max_size);
}

fn fetchBoundedAlloc(
    allocator: Allocator,
    client: *std.http.Client,
    request_kind: TokenHttpRequest,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    headers: []const std.http.Header,
) ![]u8 {
    const storage = try allocator.alloc(u8, max_response_bytes);
    defer allocator.free(storage);
    var writer: std.Io.Writer = .fixed(storage);
    // See artifactRequestAlloc: redirects are forbidden, so authentication
    // headers must use extra_headers to work around Zig 0.16.
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .response_writer = &writer,
        .redirect_behavior = .not_allowed,
        .extra_headers = headers,
    });
    if (result.status != .ok)
        return tokenHttpStatusError(request_kind, result.status);
    return allocator.dupe(u8, writer.buffered());
}

fn tokenHttpStatusError(
    request_kind: TokenHttpRequest,
    status: std.http.Status,
) anyerror {
    const status_code = @intFromEnum(status);
    return switch (request_kind) {
        .github_oidc => switch (status_code) {
            400 => error.GithubOidcBadRequest,
            401 => error.GithubOidcUnauthorized,
            403 => error.GithubOidcForbidden,
            429 => error.GithubOidcRateLimited,
            500...599 => error.GithubOidcServerError,
            else => error.GithubOidcUnexpectedHttpStatus,
        },
        .azure_token_exchange => switch (status_code) {
            400 => error.AzureTokenExchangeBadRequest,
            401 => error.AzureTokenExchangeUnauthorized,
            403 => error.AzureTokenExchangeForbidden,
            429 => error.AzureTokenExchangeRateLimited,
            500...599 => error.AzureTokenExchangeServerError,
            else => error.AzureTokenExchangeUnexpectedHttpStatus,
        },
    };
}

fn appendOidcAudienceAlloc(
    allocator: Allocator,
    request_url: []const u8,
) ![]u8 {
    if (std.mem.indexOf(u8, request_url, "audience=") != null)
        return error.UnexpectedOidcAudience;
    const separator: u8 = if (std.mem.indexOfScalar(u8, request_url, '?') == null)
        '?'
    else
        '&';
    return std.fmt.allocPrint(
        allocator,
        "{s}{c}audience={s}",
        .{ request_url, separator, oidc_audience },
    );
}

fn formEncodeAlloc(
    allocator: Allocator,
    fields: []const struct { []const u8, []const u8 },
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (fields, 0..) |field, index| {
        if (index != 0) try output.writer.writeByte('&');
        try writeFormComponent(&output.writer, field[0]);
        try output.writer.writeByte('=');
        try writeFormComponent(&output.writer, field[1]);
    }
    return output.toOwnedSlice();
}

fn writeFormComponent(writer: *std.Io.Writer, value: []const u8) !void {
    var start: usize = 0;
    for (value, 0..) |byte, index| {
        if (std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '.' or byte == '_' or byte == '~')
        {
            continue;
        }
        try writer.print("{s}%{X:0>2}", .{ value[start..index], byte });
        start = index + 1;
    }
    try writer.writeAll(value[start..]);
}

fn validateOidcRequestUrl(url: []const u8) !void {
    const https_prefix = "https://";
    if (!std.mem.startsWith(u8, url, https_prefix) or
        std.mem.indexOfScalar(u8, url, '#') != null or
        std.mem.indexOfAny(u8, url, " \t\r\n") != null)
    {
        return error.InvalidGithubOidcUrl;
    }
    const authority_end = std.mem.indexOfScalarPos(
        u8,
        url,
        https_prefix.len,
        '/',
    ) orelse return error.InvalidGithubOidcUrl;
    const host = url[https_prefix.len..authority_end];
    if (host.len <= github_actions_host_suffix.len or
        !std.mem.endsWith(u8, host, github_actions_host_suffix))
    {
        return error.InvalidGithubOidcUrl;
    }
    const subdomain = host[0 .. host.len - github_actions_host_suffix.len];
    if (subdomain.len == 0 or std.mem.endsWith(u8, subdomain, "."))
        return error.InvalidGithubOidcUrl;
    for (subdomain) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or
            byte == '-' or byte == '.'))
        {
            return error.InvalidGithubOidcUrl;
        }
    }
}

fn normalizeArtifactSigningEndpointAlloc(
    allocator: Allocator,
    endpoint: []const u8,
) ![]u8 {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, endpoint, prefix) or
        std.mem.indexOfAny(u8, endpoint, "?#% \t\r\n") != null)
    {
        return error.InvalidArtifactSigningEndpoint;
    }
    var normalized = endpoint;
    if (std.mem.endsWith(u8, normalized, "/"))
        normalized = normalized[0 .. normalized.len - 1];
    const host = normalized[prefix.len..];
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, '/') != null or
        !std.mem.endsWith(u8, host, ".codesigning.azure.net"))
    {
        return error.InvalidArtifactSigningEndpoint;
    }
    const regional_name = host[0 .. host.len - ".codesigning.azure.net".len];
    if (regional_name.len == 0 or std.mem.endsWith(u8, regional_name, "."))
        return error.InvalidArtifactSigningEndpoint;
    for (host) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or
            byte == '-' or byte == '.'))
        {
            return error.InvalidArtifactSigningEndpoint;
        }
    }
    return allocator.dupe(u8, normalized);
}

fn validatePathSegment(value: []const u8) !void {
    if (value.len == 0 or value.len > 128)
        return error.InvalidArtifactSigningResourceName;
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or
            byte == '_' or byte == '.'))
        {
            return error.InvalidArtifactSigningResourceName;
        }
    }
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

test "Artifact Signing certificate payload uses nested MIME base64" {
    const decoded = try decodeMimeBase64Alloc(
        std.testing.allocator,
        "MAMC\r\nAQE=\r\n",
        1024,
    );
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x03, 0x02, 0x01, 0x01 },
        decoded,
    );
}

test "certificate PEM encoding round trips canonical DER" {
    const certificate_der = testCertificateDer();
    const pem = try encodePemCertificateAlloc(
        std.testing.allocator,
        certificate_der,
    );
    defer std.testing.allocator.free(pem);
    const decoded = try decodePemCertificateAlloc(std.testing.allocator, pem);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, certificate_der, decoded);
}

test "form encoding protects assertion delimiters" {
    const encoded = try formEncodeAlloc(std.testing.allocator, &.{
        .{ "scope", artifact_signing_scope },
        .{ "assertion", "a+b/c=d" },
    });
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings(
        "scope=https%3A%2F%2Fcodesigning.azure.net%2F.default&" ++
            "assertion=a%2Bb%2Fc%3Dd",
        encoded,
    );
}

test "OIDC audience is appended without replacing protected query data" {
    const with_query = try appendOidcAudienceAlloc(
        std.testing.allocator,
        "https://vstoken.actions.githubusercontent.com/token?api-version=2.0",
    );
    defer std.testing.allocator.free(with_query);
    try std.testing.expectEqualStrings(
        "https://vstoken.actions.githubusercontent.com/token?api-version=2.0&audience=" ++ oidc_audience,
        with_query,
    );
    try std.testing.expectError(
        error.UnexpectedOidcAudience,
        appendOidcAudienceAlloc(
            std.testing.allocator,
            "https://vstoken.actions.githubusercontent.com/token?audience=wrong",
        ),
    );
}

test "token HTTP failures identify the rejected exchange" {
    try std.testing.expectEqual(
        error.GithubOidcUnauthorized,
        tokenHttpStatusError(.github_oidc, .unauthorized),
    );
    try std.testing.expectEqual(
        error.AzureTokenExchangeBadRequest,
        tokenHttpStatusError(.azure_token_exchange, .bad_request),
    );
    try std.testing.expectEqual(
        error.AzureTokenExchangeServerError,
        tokenHttpStatusError(.azure_token_exchange, .service_unavailable),
    );
}

test "OIDC URL accepts GitHub-controlled Actions hosts only" {
    try validateOidcRequestUrl(
        "https://vstoken.actions.githubusercontent.com/token?api-version=2.0",
    );
    try validateOidcRequestUrl(
        "https://results-receiver.actions.githubusercontent.com/twirp/token?api-version=2.0",
    );
    const invalid = [_][]const u8{
        "http://vstoken.actions.githubusercontent.com/token",
        "https://actions.githubusercontent.com/token",
        "https://vstoken.actions.githubusercontent.com.evil.example/token",
        "https://vstoken.actions.githubusercontent.com@evil.example/token",
        "https://vstoken.actions.githubusercontent.com:443/token",
        "https://VSTOKEN.actions.githubusercontent.com/token",
        "https://vstoken.actions.githubusercontent.com/token#fragment",
        "https://vstoken.actions.githubusercontent.com/token\n",
    };
    for (invalid) |url| {
        try std.testing.expectError(
            error.InvalidGithubOidcUrl,
            validateOidcRequestUrl(url),
        );
    }
}

test "Artifact Signing endpoints and resource names are constrained" {
    const endpoint = try normalizeArtifactSigningEndpointAlloc(
        std.testing.allocator,
        "https://wus.codesigning.azure.net/",
    );
    defer std.testing.allocator.free(endpoint);
    try std.testing.expectEqualStrings(
        "https://wus.codesigning.azure.net",
        endpoint,
    );
    try validatePathSegment("cataggar");
    try validatePathSegment("vmiz-uki");
    try std.testing.expectError(
        error.InvalidArtifactSigningEndpoint,
        normalizeArtifactSigningEndpointAlloc(
            std.testing.allocator,
            "https://codesigning.azure.net.evil.example/",
        ),
    );
    try std.testing.expectError(
        error.InvalidArtifactSigningEndpoint,
        normalizeArtifactSigningEndpointAlloc(
            std.testing.allocator,
            "http://wus.codesigning.azure.net/",
        ),
    );
    try std.testing.expectError(
        error.InvalidArtifactSigningResourceName,
        validatePathSegment("../vmiz"),
    );
}

test "Artifact Signing uses padded standard base64 and exact operation URLs" {
    const decoded = try decodeStandardBase64Alloc(
        std.testing.allocator,
        "AAECAwQ=",
        8,
    );
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 1, 2, 3, 4 },
        decoded,
    );
    const poll_url = try expectedArtifactSigningPollUrlAlloc(
        std.testing.allocator,
        .{
            .endpoint = "https://wus.codesigning.azure.net",
            .account = "cataggar",
            .profile = "vmiz-uki",
        },
        "00000000-0000-4000-8000-000000000000",
    );
    defer std.testing.allocator.free(poll_url);
    try std.testing.expectEqualStrings(
        "https://wus.codesigning.azure.net/codesigningaccounts/cataggar/" ++
            "certificateprofiles/vmiz-uki/sign/" ++
            "00000000-0000-4000-8000-000000000000?" ++
            "api-version=2024-06-15",
        poll_url,
    );
    const config: ArtifactSigningConfig = .{
        .endpoint = "https://wus.codesigning.azure.net",
        .account = "cataggar",
        .profile = "vmiz-uki",
    };
    try std.testing.expectEqualStrings(
        "00000000-0000-4000-8000-000000000000",
        try validateArtifactSigningOperationLocation(
            std.testing.allocator,
            config,
            poll_url,
        ),
    );
    const invalid_locations = [_][]const u8{
        "https://eus.codesigning.azure.net/codesigningaccounts/cataggar/" ++
            "certificateprofiles/vmiz-uki/sign/" ++
            "00000000-0000-4000-8000-000000000000?api-version=2024-06-15",
        "https://wus.codesigning.azure.net/codesigningaccounts/other/" ++
            "certificateprofiles/vmiz-uki/sign/" ++
            "00000000-0000-4000-8000-000000000000?api-version=2024-06-15",
        "https://wus.codesigning.azure.net/codesigningaccounts/cataggar/" ++
            "certificateprofiles/other/sign/" ++
            "00000000-0000-4000-8000-000000000000?api-version=2024-06-15",
        "https://wus.codesigning.azure.net/codesigningaccounts/cataggar/" ++
            "certificateprofiles/vmiz-uki/sign/" ++
            "00000000-0000-4000-8000-000000000000?api-version=2022-06-15",
    };
    for (invalid_locations) |location| {
        try std.testing.expectError(
            error.InvalidArtifactSigningOperationLocation,
            validateArtifactSigningOperationLocation(
                std.testing.allocator,
                config,
                location,
            ),
        );
    }
    try std.testing.expectError(
        error.InvalidArtifactSigningOperationId,
        validateArtifactSigningOperationLocation(
            std.testing.allocator,
            config,
            "https://wus.codesigning.azure.net/codesigningaccounts/cataggar/" ++
                "certificateprofiles/vmiz-uki/sign/not-a-uuid?" ++
                "api-version=2024-06-15",
        ),
    );
}

test "Artifact Signing distinguishes malformed JSON from invalid operation schema" {
    try std.testing.expectError(
        error.InvalidArtifactSigningOperationJson,
        parseArtifactOperation(std.testing.allocator, "not-json"),
    );
    try std.testing.expectError(
        error.InvalidArtifactSigningOperationSchema,
        parseArtifactOperation(
            std.testing.allocator,
            "{\"id\":1,\"status\":\"Running\"}",
        ),
    );
}

test "PEM certificate decoder accepts one canonical certificate block" {
    const der = try decodePemCertificateAlloc(
        std.testing.allocator,
        "-----BEGIN CERTIFICATE-----\n" ++
            "MIGSMH2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQD\n" ++
            "DAtUZXN0IFNpZ25lcjAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEw\n" ++
            "MDAwMDBaMBYxFDASBgNVBAMMC1Rlc3QgU2lnbmVyMBQwDQYJKoZI\n" ++
            "hvcNAQEBBQADAwAwADANBgkqhkiG9w0BAQsFAAMCAAA=\n" ++
            "-----END CERTIFICATE-----\n",
    );
    defer std.testing.allocator.free(der);
    try std.testing.expectEqualSlices(u8, testCertificateDer(), der);
    try std.testing.expectError(
        error.InvalidCertificatePem,
        decodePemCertificateAlloc(
            std.testing.allocator,
            "prefix\n-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----",
        ),
    );
}

fn testCertificateDer() []const u8 {
    return "\x30\x81\x92\x30\x7d\xa0\x03\x02\x01\x02\x02\x01\x01" ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" ++
        "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
        "Test Signer" ++
        "\x30\x1e\x17\x0d\x32\x36\x30\x31\x30\x31\x30\x30\x30\x30" ++
        "\x30\x30\x5a\x17\x0d\x32\x37\x30\x31\x30\x31\x30\x30\x30" ++
        "\x30\x30\x30\x5a" ++
        "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
        "Test Signer" ++
        "\x30\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" ++
        "\x01\x05\x00\x03\x03\x00\x30\x00" ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05" ++
        "\x00\x03\x02\x00\x00";
}

const MockArtifactSigningScenario = enum {
    success,
    failed,
    canceled,
    timeout,
    malformed_base64,
    wrong_poll_operation_id,
    wrong_operation_location,
    redirect,
};

const MockArtifactSigningServer = struct {
    scenario: MockArtifactSigningScenario,
    poll_url: []const u8,
    success_body: []const u8,
    err: ?anyerror = null,
};

fn mockArtifactSigningRequestCount(
    scenario: MockArtifactSigningScenario,
) usize {
    return switch (scenario) {
        .success, .timeout => 3,
        .failed,
        .canceled,
        .malformed_base64,
        .wrong_poll_operation_id,
        => 2,
        .wrong_operation_location, .redirect => 1,
    };
}

fn runMockArtifactSigningServer(
    io: Io,
    listener: *std.Io.net.Server,
    context: *MockArtifactSigningServer,
) void {
    runMockArtifactSigningServerFallible(io, listener, context) catch |err| {
        context.err = err;
    };
}

fn runMockArtifactSigningServerFallible(
    io: Io,
    listener: *std.Io.net.Server,
    context: *MockArtifactSigningServer,
) !void {
    var stream = try listener.accept(io);
    defer stream.close(io);
    var input_buffer: [4096]u8 = undefined;
    var output_buffer: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &input_buffer);
    var stream_writer = stream.writer(io, &output_buffer);
    var server: std.http.Server = .init(
        &stream_reader.interface,
        &stream_writer.interface,
    );

    const operation_id = "00000000-0000-4000-8000-000000000000";
    const accepted_body = "";
    const in_progress_body =
        "{\"id\":\"" ++ operation_id ++ "\",\"status\":\"InProgress\"," ++
        "\"result\":{\"signature\":null,\"signingCertificate\":null}}";
    const running_body =
        "{\"id\":\"" ++ operation_id ++ "\",\"status\":\"Running\"," ++
        "\"result\":{\"signature\":null,\"signingCertificate\":null}}";
    const failed_body =
        "{\"id\":\"" ++ operation_id ++ "\",\"status\":\"Failed\"," ++
        "\"error\":{\"code\":\"MockFailure\",\"message\":\"redacted\"}}";
    const canceled_body =
        "{\"id\":\"" ++ operation_id ++ "\",\"status\":\"Canceled\"}";
    const malformed_body =
        "{\"id\":\"" ++ operation_id ++ "\",\"status\":\"Succeeded\"," ++
        "\"result\":{\"signature\":\"not-base64\",\"signingCertificate\":" ++
        "\"MAMCAQE=\"}}";
    const wrong_id_body =
        "{\"id\":\"11111111-1111-4111-8111-111111111111\"," ++
        "\"status\":\"Running\"}";

    var handled: usize = 0;
    while (handled < mockArtifactSigningRequestCount(context.scenario)) : (handled += 1) {
        var request = try server.receiveHead();
        var accepts_identity = false;
        var request_headers = request.iterateHeaders();
        while (request_headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Accept-Encoding") and
                std.ascii.eqlIgnoreCase(header.value, "identity"))
            {
                accepts_identity = true;
            }
        }
        if (!accepts_identity)
            return error.UnexpectedMockArtifactSigningEncoding;
        if (handled == 0) {
            if (request.head.method != .POST)
                return error.UnexpectedMockArtifactSigningRequest;
            if (context.scenario == .redirect) {
                try request.respond("", .{
                    .status = .temporary_redirect,
                    .extra_headers = &.{
                        .{ .name = "Location", .value = "https://evil.example/" },
                    },
                });
                continue;
            }
            const operation_location = if (context.scenario ==
                .wrong_operation_location)
                "https://evil.example/operation"
            else
                context.poll_url;
            try request.respond(accepted_body, .{
                .status = .accepted,
                .extra_headers = &.{
                    .{
                        .name = "Operation-Location",
                        .value = operation_location,
                    },
                },
            });
            continue;
        }
        if (request.head.method != .GET)
            return error.UnexpectedMockArtifactSigningRequest;
        const body = switch (context.scenario) {
            .success => if (handled == 1)
                in_progress_body
            else
                context.success_body,
            .failed => failed_body,
            .canceled => canceled_body,
            .timeout => running_body,
            .malformed_base64 => malformed_body,
            .wrong_poll_operation_id => wrong_id_body,
            .wrong_operation_location, .redirect => unreachable,
        };
        try request.respond(body, .{});
    }
}

fn runMockArtifactSigningScenario(
    allocator: Allocator,
    io: Io,
    scenario: MockArtifactSigningScenario,
) !ArtifactSigningResult {
    const port: u16 = 28910 + @as(u16, @intFromEnum(scenario));
    var listen_address: std.Io.net.IpAddress = .{
        .ip4 = .{
            .bytes = .{ 127, 0, 0, 1 },
            .port = port,
        },
    };
    var listener = try listen_address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const endpoint = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{port},
    );
    defer allocator.free(endpoint);
    const config: ArtifactSigningConfig = .{
        .endpoint = endpoint,
        .account = "cataggar",
        .profile = "vmiz-uki",
    };
    const poll_url = try expectedArtifactSigningPollUrlAlloc(
        allocator,
        config,
        "00000000-0000-4000-8000-000000000000",
    );
    defer allocator.free(poll_url);
    const signature = [_]u8{0x5a} ** 256;
    const signature_text = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(signature.len),
    );
    defer allocator.free(signature_text);
    _ = std.base64.standard.Encoder.encode(signature_text, &signature);
    const success_body = try std.json.Stringify.valueAlloc(
        allocator,
        .{
            .id = "00000000-0000-4000-8000-000000000000",
            .status = "Succeeded",
            .result = .{
                .signature = signature_text,
                .signingCertificate = "TUFNQ0FRRT0=",
            },
        },
        .{},
    );
    defer allocator.free(success_body);
    var context: MockArtifactSigningServer = .{
        .scenario = scenario,
        .poll_url = poll_url,
        .success_body = success_body,
    };
    const thread = try std.Thread.spawn(
        .{},
        runMockArtifactSigningServer,
        .{ io, &listener, &context },
    );

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    const result = signDigestWithArtifactSigningAlloc(
        io,
        allocator,
        &client,
        config,
        "test-token",
        [_]u8{0xa5} ** 32,
        .{ .max_attempts = 2, .sleep = false },
    ) catch |err| {
        thread.join();
        if (context.err) |server_err| return server_err;
        return err;
    };
    thread.join();
    if (context.err) |err| {
        var mutable_result = result;
        mutable_result.deinit(allocator);
        return err;
    }
    return result;
}

test "Artifact Signing submit and polling decode the returned bundle and signature" {
    var result = try runMockArtifactSigningScenario(
        std.testing.allocator,
        std.testing.io,
        .success,
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 256), result.signature.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x03, 0x02, 0x01, 0x01 },
        result.certificate_bundle,
    );
    try std.testing.expectEqualStrings(
        "00000000-0000-4000-8000-000000000000",
        result.operation_id,
    );
}

test "Artifact Signing rejects terminal failures, timeouts, and malformed results" {
    try std.testing.expectError(
        error.ArtifactSigningOperationFailed,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .failed,
        ),
    );
    try std.testing.expectError(
        error.ArtifactSigningOperationCanceled,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .canceled,
        ),
    );
    try std.testing.expectError(
        error.ArtifactSigningTimedOut,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .timeout,
        ),
    );
    try std.testing.expectError(
        error.InvalidPadding,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .malformed_base64,
        ),
    );
    try std.testing.expectError(
        error.ArtifactSigningOperationIdMismatch,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .wrong_poll_operation_id,
        ),
    );
}

test "Artifact Signing rejects untrusted operation URLs and redirects" {
    try std.testing.expectError(
        error.InvalidArtifactSigningOperationLocation,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .wrong_operation_location,
        ),
    );
    try std.testing.expectError(
        error.TooManyHttpRedirects,
        runMockArtifactSigningScenario(
            std.testing.allocator,
            std.testing.io,
            .redirect,
        ),
    );
}
