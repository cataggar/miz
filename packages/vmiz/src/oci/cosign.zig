//! Decides whether a cosign key-pair signature vouches for an image digest.
//!
//! This is the half of the registry signature story that needs no network. It
//! takes a public key the caller declared, the raw bytes of a simple-signing
//! payload, and the base64 signature that travelled with it, and answers one
//! question: did the holder of that key sign a statement naming this image?
//! Finding those bytes in a registry is a separate concern and lives
//! elsewhere; nothing here opens a socket, keeps a session or allocates on
//! behalf of a transport.
//!
//! `uki_signing.zig` is the nearest precedent and the shape transfers: state
//! the trust anchor up front, re-derive from the returned bytes everything you
//! go on to assert, and be explicit about what is not checked. The refusal
//! does not transfer. That module says plainly that "the RSA signature is not
//! verified and no chain is built", because it produces a signature and
//! declines to judge trust. This module exists only to judge trust, so it
//! performs the key operation itself.
//!
//! What is deliberately not checked, and is not a gap to be filled in
//! passing: no certificate chain is built, no revocation is consulted, no
//! transparency-log inclusion proof is fetched and no signer identity is
//! matched. Those are keyless verification, which needs Fulcio, Rekor and an
//! OIDC identity policy -- each a larger thing than all of this. A caller that
//! wants them wants a different module, not more arguments to this one.
//!
//! The signature scheme is fixed at ECDSA P-256 with SHA-256 because the
//! cosign specification requires it to be: "no information about the signature
//! scheme is included in the object; clients must determine the signature
//! scheme out-of-band during the verification process". So the scheme is a
//! property of the declared policy, not something read from the artifact. A
//! key on another curve is refused by name rather than misread.

const std = @import("std");

const content = @import("content.zig");

const Allocator = std.mem.Allocator;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The layer media type that marks a simple-signing payload inside a cosign
/// signature manifest.
pub const payload_media_type = "application/vnd.dev.cosign.simplesigning.v1+json";

/// The descriptor annotation carrying the base64 DER signature over the
/// payload blob.
pub const signature_annotation = "dev.cosignproject.cosign/signature";

/// The `critical.type` value that marks a payload as a cosign container image
/// signature rather than some other simple-signing statement.
pub const critical_type = "cosign container image signature";

/// A simple-signing payload is a small JSON object. The bound exists so a
/// caller reading one from a registry has a size to refuse past, and so this
/// module never parses an unbounded blob.
pub const max_payload_bytes = 64 * 1024;

/// A P-256 SPKI public key PEM is ~180 bytes. The bound is generous enough to
/// hold an RSA key long enough to name it in a refusal.
pub const max_public_key_pem_bytes = 8 * 1024;
const max_public_key_der_bytes = 4 * 1024;

/// A DER ECDSA P-256 signature is at most 72 bytes, so ~100 base64
/// characters. The bound leaves room for whitespace and refuses anything that
/// is plainly not a signature before decoding it.
pub const max_signature_base64_bytes = 512;
const max_signature_der_bytes = Ecdsa.Signature.der_encoded_length_max;

/// Everything that can go wrong between a declared key and a verdict. A closed
/// set, so a caller that embeds verification in a larger operation still has
/// an error union naming each distinct failure -- in particular, a signature
/// that does not verify and a signature that verifies over the wrong image are
/// different errors, because they mean different things.
pub const Error = Allocator.Error || error{
    /// The declared key is not a `PUBLIC KEY` PEM block, or its base64 body is
    /// not decodable.
    InvalidPublicKeyPem,
    /// The key decodes but is not an elliptic-curve key at all -- an RSA or
    /// Ed25519 key, say.
    UnsupportedPublicKeyAlgorithm,
    /// The key is an EC key on a curve other than P-256.
    UnsupportedPublicKeyCurve,
    /// The key claims to be P-256 but its SubjectPublicKeyInfo is malformed or
    /// its point is not on the curve.
    InvalidPublicKey,
    /// The signature annotation is not base64, or does not decode to a DER
    /// ECDSA signature.
    InvalidSignatureEncoding,
    /// The signature is well formed and does not verify over these payload
    /// bytes with this key.
    SignatureMismatch,
    /// The payload is not JSON, or is JSON that is not a simple-signing
    /// statement.
    InvalidPayload,
    /// The payload is simple-signing but `critical.type` is not the cosign
    /// container image signature type.
    UnexpectedPayloadType,
    /// The signature is valid and vouches for a different image. This is the
    /// failure that stops a genuine signature for image A from authorising
    /// image B.
    PayloadImageMismatch,
};

/// A verified-nothing pair straight off a signature manifest: the payload blob
/// exactly as the registry served it, and the annotation text beside it.
///
/// The payload bytes must be the bytes the payload's own digest covers, passed
/// through unchanged. The signature is over those bytes, so re-serialising the
/// JSON -- even to something equivalent -- destroys the signature.
pub const SignedPayload = struct {
    payload: []const u8,
    signature: []const u8,
};

pub const PublicKey = Ecdsa.PublicKey;
pub const Signature = Ecdsa.Signature;

/// Decides whether `signed` is a cosign signature, made with `key`, over a
/// statement naming `image`.
///
/// The order is deliberate: the key operation runs first, over the raw bytes,
/// and only a payload that has already been proved to come from the key holder
/// is parsed for what it claims. Reversing that would let an unauthenticated
/// blob steer the parser.
pub fn verify(
    allocator: Allocator,
    signed: SignedPayload,
    key: PublicKey,
    image: content.Digest,
) Error!void {
    const signature = try parseSignature(signed.signature);
    try verifySignature(signed.payload, signature, key);
    try checkPayload(allocator, signed.payload, image);
}

/// Reads a `PUBLIC KEY` PEM block holding an ECDSA P-256 SubjectPublicKeyInfo.
///
/// The trust anchor is public material, so it is legitimate for it to be
/// declared by value as well as by path -- see `TrustSource` in
/// `customize.zig`, which draws the same line for a UKI signing certificate.
/// A key that is not P-256 is refused rather than coerced; `describePublicKey`
/// names what was refused.
pub fn parsePublicKeyPem(pem: []const u8) Error!PublicKey {
    var der_buffer: [max_public_key_der_bytes]u8 = undefined;
    const der = try decodePublicKeyPem(pem, &der_buffer);
    const info = try parseSubjectPublicKeyInfo(der);
    switch (info.algorithm) {
        .ec => {},
        .other => return error.UnsupportedPublicKeyAlgorithm,
    }
    if (info.curve != .p256) return error.UnsupportedPublicKeyCurve;
    return PublicKey.fromSec1(info.key_bytes) catch error.InvalidPublicKey;
}

/// Names the key a PEM declares, so a refusal can say what it rejected rather
/// than only that it rejected something. Returns null when the bytes are not a
/// public key this module can identify at all.
pub fn describePublicKey(pem: []const u8) ?[]const u8 {
    var der_buffer: [max_public_key_der_bytes]u8 = undefined;
    const der = decodePublicKeyPem(pem, &der_buffer) catch return null;
    const info = parseSubjectPublicKeyInfo(der) catch return null;
    return switch (info.algorithm) {
        .other => |name| name,
        .ec => switch (info.curve) {
            .p256 => "ECDSA P-256",
            .p384 => "ECDSA P-384 (secp384r1)",
            .p521 => "ECDSA P-521 (secp521r1)",
            .secp256k1 => "ECDSA secp256k1",
            .unknown => "an elliptic-curve key on an unrecognised curve",
        },
    };
}

/// Decodes the base64 DER text of a `dev.cosignproject.cosign/signature`
/// annotation.
pub fn parseSignature(annotation: []const u8) Error!Signature {
    const text = std.mem.trim(u8, annotation, " \t\r\n");
    if (text.len == 0 or text.len > max_signature_base64_bytes)
        return error.InvalidSignatureEncoding;
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch
        return error.InvalidSignatureEncoding;
    if (size == 0 or size > max_signature_der_bytes)
        return error.InvalidSignatureEncoding;
    var der: [max_signature_der_bytes]u8 = undefined;
    std.base64.standard.Decoder.decode(der[0..size], text) catch
        return error.InvalidSignatureEncoding;
    return Signature.fromDer(der[0..size]) catch error.InvalidSignatureEncoding;
}

/// Performs the key operation over the payload bytes and nothing else.
pub fn verifySignature(
    payload: []const u8,
    signature: Signature,
    key: PublicKey,
) Error!void {
    signature.verify(payload, key) catch return error.SignatureMismatch;
}

/// Checks that a simple-signing payload is a cosign container image signature
/// naming `image`.
///
/// `critical.identity.docker-reference` is read by nobody here, on purpose.
/// cosign's specification says the field "is ignored", and it is ignored in
/// practice: the signature on `ghcr.io/sigstore/cosign/cosign` carries the
/// reference `gcr.io/projectsigstore/cosign`. Checking it would invent a
/// refusal cosign does not make and would fail on genuine artifacts.
pub fn checkPayload(
    allocator: Allocator,
    payload: []const u8,
    image: content.Digest,
) Error!void {
    if (payload.len == 0 or payload.len > max_payload_bytes)
        return error.InvalidPayload;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPayload,
    };
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidPayload,
    };
    const critical = switch (root.get("critical") orelse return error.InvalidPayload) {
        .object => |object| object,
        else => return error.InvalidPayload,
    };
    const payload_type = switch (critical.get("type") orelse return error.InvalidPayload) {
        .string => |text| text,
        else => return error.InvalidPayload,
    };
    if (!std.mem.eql(u8, payload_type, critical_type))
        return error.UnexpectedPayloadType;

    const image_object = switch (critical.get("image") orelse return error.InvalidPayload) {
        .object => |object| object,
        else => return error.InvalidPayload,
    };
    const claimed = try manifestDigestField(image_object);
    const claimed_digest = content.Digest.parse(claimed) catch return error.InvalidPayload;
    if (!std.mem.eql(u8, &claimed_digest.bytes, &image.bytes))
        return error.PayloadImageMismatch;
}

/// Reads `critical.image.docker-manifest-digest` under either spelling that
/// occurs in the wild.
///
/// cosign emits the lowercase form -- verified against a real artifact -- but
/// the specification's own example shows `Docker-manifest-digest`, and Go's
/// JSON decoder matches field names case-insensitively, so cosign itself
/// accepts both. Refusing the capitalised form would refuse a payload cosign
/// accepts. A payload carrying both spellings with different digests is not a
/// payload with an answer, so it is refused rather than guessed at.
fn manifestDigestField(image_object: std.json.ObjectMap) Error![]const u8 {
    const lower = image_object.get("docker-manifest-digest");
    const upper = image_object.get("Docker-manifest-digest");
    const chosen = lower orelse upper orelse return error.InvalidPayload;
    const text = switch (chosen) {
        .string => |value| value,
        else => return error.InvalidPayload,
    };
    if (lower != null and upper != null) {
        const other = switch (upper.?) {
            .string => |value| value,
            else => return error.InvalidPayload,
        };
        if (!std.mem.eql(u8, text, other)) return error.InvalidPayload;
    }
    return text;
}

// ---- SubjectPublicKeyInfo ----
//
// The DER walked here is small and fully specified, so it gets a strict local
// reader rather than a shared one. `authenticode.zig` has an equivalent
// `parseDerElement`, but it is private to a module about PE images and CMS,
// and reaching for it would couple the OCI path to Authenticode for forty
// lines. `std.crypto.Certificate.der.Element.parse` is public but indexes its
// input without bounds checks, which is the wrong shape for bytes a registry
// handed us.

const ec_public_key_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const rsa_encryption_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const ed25519_oid = [_]u8{ 0x2b, 0x65, 0x70 };
const p256_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const p384_oid = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const p521_oid = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x23 };
const secp256k1_oid = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x0a };

const Algorithm = union(enum) {
    ec,
    /// A key this module will not use, carrying a name for the refusal.
    other: []const u8,
};

const Curve = enum { p256, p384, p521, secp256k1, unknown };

const SubjectPublicKeyInfo = struct {
    algorithm: Algorithm,
    curve: Curve,
    key_bytes: []const u8,
};

fn parseSubjectPublicKeyInfo(der: []const u8) Error!SubjectPublicKeyInfo {
    const info = try derElement(der, 0, 0x30);
    if (info.end != der.len) return error.InvalidPublicKey;
    const algorithm_identifier = try derElement(der, info.content_start, 0x30);
    const algorithm_oid = try derElement(der, algorithm_identifier.content_start, 0x06);
    const algorithm_bytes = der[algorithm_oid.content_start..algorithm_oid.end];

    if (!std.mem.eql(u8, algorithm_bytes, &ec_public_key_oid)) {
        return .{
            .algorithm = .{ .other = namedAlgorithm(algorithm_bytes) },
            .curve = .unknown,
            .key_bytes = &.{},
        };
    }

    const curve_oid = try derElement(der, algorithm_oid.end, 0x06);
    if (curve_oid.end != algorithm_identifier.end) return error.InvalidPublicKey;
    const curve_bytes = der[curve_oid.content_start..curve_oid.end];

    const key = try derElement(der, algorithm_identifier.end, 0x03);
    if (key.end != info.end) return error.InvalidPublicKey;
    if (key.content_start == key.end) return error.InvalidPublicKey;
    // A public key never has unused trailing bits.
    if (der[key.content_start] != 0) return error.InvalidPublicKey;

    return .{
        .algorithm = .ec,
        .curve = namedCurve(curve_bytes),
        .key_bytes = der[key.content_start + 1 .. key.end],
    };
}

fn namedAlgorithm(oid: []const u8) []const u8 {
    if (std.mem.eql(u8, oid, &rsa_encryption_oid)) return "an RSA key";
    if (std.mem.eql(u8, oid, &ed25519_oid)) return "an Ed25519 key";
    return "a key of an unrecognised algorithm";
}

fn namedCurve(oid: []const u8) Curve {
    if (std.mem.eql(u8, oid, &p256_oid)) return .p256;
    if (std.mem.eql(u8, oid, &p384_oid)) return .p384;
    if (std.mem.eql(u8, oid, &p521_oid)) return .p521;
    if (std.mem.eql(u8, oid, &secp256k1_oid)) return .secp256k1;
    return .unknown;
}

const DerElement = struct {
    content_start: usize,
    end: usize,
};

fn derElement(bytes: []const u8, start: usize, expected_tag: u8) Error!DerElement {
    const header_end = std.math.add(usize, start, 2) catch return error.InvalidPublicKey;
    if (header_end > bytes.len) return error.InvalidPublicKey;
    if (bytes[start] != expected_tag) return error.InvalidPublicKey;
    const length_byte = bytes[start + 1];
    var content_start = header_end;
    var length: usize = 0;
    if (length_byte < 0x80) {
        length = length_byte;
    } else {
        const count: usize = length_byte & 0x7f;
        if (count == 0 or count > @sizeOf(u32)) return error.InvalidPublicKey;
        const length_end = std.math.add(usize, content_start, count) catch
            return error.InvalidPublicKey;
        if (length_end > bytes.len or bytes[content_start] == 0)
            return error.InvalidPublicKey;
        for (bytes[content_start..length_end]) |byte| {
            length = std.math.mul(usize, length, 256) catch return error.InvalidPublicKey;
            length = std.math.add(usize, length, byte) catch return error.InvalidPublicKey;
        }
        if (length < 128) return error.InvalidPublicKey;
        content_start = length_end;
    }
    const end = std.math.add(usize, content_start, length) catch
        return error.InvalidPublicKey;
    if (end > bytes.len) return error.InvalidPublicKey;
    return .{ .content_start = content_start, .end = end };
}

fn decodePublicKeyPem(pem: []const u8, buffer: []u8) Error![]const u8 {
    const begin_marker = "-----BEGIN PUBLIC KEY-----";
    const end_marker = "-----END PUBLIC KEY-----";
    if (pem.len > max_public_key_pem_bytes) return error.InvalidPublicKeyPem;
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse
        return error.InvalidPublicKeyPem;
    if (std.mem.trim(u8, pem[0..begin], " \t\r\n").len != 0)
        return error.InvalidPublicKeyPem;
    const body_start = begin + begin_marker.len;
    const relative_end = std.mem.indexOf(u8, pem[body_start..], end_marker) orelse
        return error.InvalidPublicKeyPem;
    const body_end = body_start + relative_end;
    const suffix = pem[body_end + end_marker.len ..];
    if (std.mem.trim(u8, suffix, " \t\r\n").len != 0)
        return error.InvalidPublicKeyPem;

    var encoded: [max_public_key_pem_bytes]u8 = undefined;
    var encoded_len: usize = 0;
    for (pem[body_start..body_end]) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        if (encoded_len == encoded.len) return error.InvalidPublicKeyPem;
        encoded[encoded_len] = byte;
        encoded_len += 1;
    }
    const encoded_slice = encoded[0..encoded_len];
    const size = std.base64.standard.Decoder.calcSizeForSlice(encoded_slice) catch
        return error.InvalidPublicKeyPem;
    if (size == 0 or size > buffer.len) return error.InvalidPublicKeyPem;
    std.base64.standard.Decoder.decode(buffer[0..size], encoded_slice) catch
        return error.InvalidPublicKeyPem;
    return buffer[0..size];
}

// ---- tests ----
//
// The fixtures below were generated once, offline, with OpenSSL 3.3.7 and are
// committed so the cryptography is testable without a registry or a key
// generator:
//
//   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
//   openssl ec -in key.pem -pubout -out pub.pem
//   openssl dgst -sha256 -sign key.pem -out payload.sig payload.json
//   base64 -w0 payload.sig
//
// Each payload below differs from `signed_payload` in exactly one respect, and
// each carries its own genuine signature, so a test that refuses one is
// refusing the thing the name says and not a broken signature.

const test_public_key_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExcx3qNu1iy1vrjdIo4nCjRaj0lp3
    \\8RSsPiSWxoQGIwfeUNMlU3tavIYwgbRbOCrz0JqtyKsye55eQf7eN+4ieQ==
    \\-----END PUBLIC KEY-----
    \\
;

const test_p384_public_key_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUTB4cU6NHMjXwM86bX45QXBLP+itLqIU
    \\vue9po3BYPFOuaBATLHAz+rj4eeQUgYLdLM90ssiNAYvbYvVHpOH4Mv3OBv/JrM8
    \\TRyKtUwRre6NgsQIWIN3nyzwBZ1JCpI7
    \\-----END PUBLIC KEY-----
    \\
;

const test_rsa_public_key_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOuLgq3iuwXsOfHlt9U3
    \\vEu9KuMTyNIVOXFzrtH6hlqcbsNLwYonkJ4GSEmOCgp5z4WnvzjrKYleSGJPcUDJ
    \\hiHy3irzuWfoFP508JzaAw3RkdmT3mBeWTXnRJPdOxg567D7dkmIUeSSS05EeMvU
    \\su1U0NdLiU5yMfi+qWpnCx/jGZXX5M3ET6ispPLQ789VlB4q5PBmFxpVFKOt0TRG
    \\/nIJT6DsWv41L8eLEPIyt0kkENuUdSO2KGDB8BFgWiuJEat9Xj6JPscPdKsiIU6L
    \\PTYOK6wzorfx/DrdSlGzWLKfEoU9badDslxd4LfcoiactyV4Sz6/+RDdqpdeLgFW
    \\iQIDAQAB
    \\-----END PUBLIC KEY-----
    \\
;

const test_image_digest =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const test_other_image_digest =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

const signed_payload: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"registry.example.com/team/app"},"image":{"docker-manifest-digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"type":"cosign container image signature"},"optional":null}
    ,
    .signature = "MEUCIBtDDdbvg7y1uKn/i0TUQQ6CYu9t2mxvLW3qbqyZVghJAiEArh85Rv8UwKLbUid6tCbbbz62EWM7rGY3VN36RwF4nmE=",
};

const signed_payload_for_other_image: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"registry.example.com/team/app"},"image":{"docker-manifest-digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"type":"cosign container image signature"},"optional":null}
    ,
    .signature = "MEQCIDz0bhoKI7Q/4P7NBkTorXtJJULpEzx2xOoHcmhy+c7MAiAHW0GA8lvhghHYQQw5bj1dMK6MMMLRXmpVH4darW2uDA==",
};

const signed_payload_with_other_type: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"registry.example.com/team/app"},"image":{"docker-manifest-digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"type":"atomic container signature"},"optional":null}
    ,
    .signature = "MEUCIQC5IxkKf5Q0dKIaTvTx07ifAnBWEJDnDGqZCawpuchToQIgBFiF3uaSuzoaGxDMe5s7tbQhDlR9JdvC3dqUa+5l39Q=",
};

const signed_payload_with_other_reference: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"some.other.registry/elsewhere/name"},"image":{"docker-manifest-digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"type":"cosign container image signature"},"optional":null}
    ,
    .signature = "MEUCICDIv0aGP1swSOJlgylPzgd3CLOWRLanMAi+cuOTi+qZAiEA9SPzOwKV621e6T3q1ubSLvDvt7HKW6ln/kKBtDFu8LI=",
};

const signed_payload_with_capitalised_digest_key: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"registry.example.com/team/app"},"image":{"Docker-manifest-digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"type":"cosign container image signature"},"optional":null}
    ,
    .signature = "MEUCIC7c03TuUO/gR8ir6+YOJHXSui1CsLUy442kqHKckBZuAiEAwwV/ysB5YRDtUFOfivpAqDbLvzBgiukvr7cB8k8Eu80=",
};

fn expectVerifies(signed: SignedPayload, image_text: []const u8) !void {
    const key = try parsePublicKeyPem(test_public_key_pem);
    const image = try content.Digest.parse(image_text);
    try verify(std.testing.allocator, signed, key, image);
}

fn expectRefused(
    expected: anyerror,
    signed: SignedPayload,
    image_text: []const u8,
) !void {
    const key = try parsePublicKeyPem(test_public_key_pem);
    const image = try content.Digest.parse(image_text);
    try std.testing.expectError(
        expected,
        verify(std.testing.allocator, signed, key, image),
    );
}

test "a cosign signature over a payload naming the image verifies with the declared key" {
    try expectVerifies(signed_payload, test_image_digest);
}

test "a signature made over different bytes does not verify" {
    // A genuine signature, by the same key, over a different payload.
    try expectRefused(error.SignatureMismatch, .{
        .payload = signed_payload.payload,
        .signature = signed_payload_for_other_image.signature,
    }, test_image_digest);
}

test "a cryptographically valid signature naming a different image is refused" {
    // The signature is genuine and the key is right; only the image the
    // payload vouches for is wrong. Without this check a real signature for
    // one image would authorise any other.
    try expectRefused(
        error.PayloadImageMismatch,
        signed_payload_for_other_image,
        test_image_digest,
    );
    try expectVerifies(signed_payload_for_other_image, test_other_image_digest);
}

test "a payload whose critical type is not a cosign signature is refused" {
    try expectRefused(
        error.UnexpectedPayloadType,
        signed_payload_with_other_type,
        test_image_digest,
    );
}

test "a payload naming a different docker-reference is accepted, as cosign does" {
    // Deliberate, and not a bug to be fixed later: the cosign specification
    // says `critical.identity.docker-reference` "is ignored", and real
    // artifacts carry a reference that does not match where they are hosted.
    try expectVerifies(signed_payload_with_other_reference, test_image_digest);
}

test "the capitalised Docker-manifest-digest spelling from the spec is accepted" {
    try expectVerifies(signed_payload_with_capitalised_digest_key, test_image_digest);
}

test "a payload carrying both digest spellings disagreeing is refused" {
    const image = try content.Digest.parse(test_image_digest);
    try std.testing.expectError(error.InvalidPayload, checkPayload(
        std.testing.allocator,
        \\{"critical":{"image":{"docker-manifest-digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","Docker-manifest-digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"type":"cosign container image signature"}}
    ,
        image,
    ));
}

test "a key on a curve other than P-256 is refused by name" {
    try std.testing.expectError(
        error.UnsupportedPublicKeyCurve,
        parsePublicKeyPem(test_p384_public_key_pem),
    );
    try std.testing.expectEqualStrings(
        "ECDSA P-384 (secp384r1)",
        describePublicKey(test_p384_public_key_pem).?,
    );
    try std.testing.expectEqualStrings(
        "ECDSA P-256",
        describePublicKey(test_public_key_pem).?,
    );
}

test "a key that is not an elliptic-curve key is refused by name" {
    try std.testing.expectError(
        error.UnsupportedPublicKeyAlgorithm,
        parsePublicKeyPem(test_rsa_public_key_pem),
    );
    try std.testing.expectEqualStrings(
        "an RSA key",
        describePublicKey(test_rsa_public_key_pem).?,
    );
}

test "malformed key material is refused rather than misparsed" {
    try std.testing.expectError(
        error.InvalidPublicKeyPem,
        parsePublicKeyPem("not a pem at all"),
    );
    try std.testing.expectError(error.InvalidPublicKeyPem, parsePublicKeyPem(
        "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
    ));
    // Truncated DER: a valid header promising more bytes than are present.
    try std.testing.expectError(error.InvalidPublicKey, parsePublicKeyPem(
        "-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----\n",
    ));
    try std.testing.expect(describePublicKey("not a pem at all") == null);
}

test "a truncated or malformed signature is refused rather than panicking" {
    try std.testing.expectError(error.InvalidSignatureEncoding, parseSignature(""));
    try std.testing.expectError(error.InvalidSignatureEncoding, parseSignature("%%%%"));
    // Valid base64, not DER.
    try std.testing.expectError(error.InvalidSignatureEncoding, parseSignature("AAAA"));
    // The genuine signature with its last base64 group removed.
    const truncated = signed_payload.signature[0 .. signed_payload.signature.len - 8];
    try std.testing.expectError(error.InvalidSignatureEncoding, parseSignature(truncated));
    // A DER header claiming a longer body than follows.
    try std.testing.expectError(error.InvalidSignatureEncoding, parseSignature("MEUCIBtD"));
}

test "a payload that is not simple signing is refused" {
    const image = try content.Digest.parse(test_image_digest);
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidPayload,
        checkPayload(allocator, "not json at all", image),
    );
    try std.testing.expectError(
        error.InvalidPayload,
        checkPayload(allocator, "[1,2,3]", image),
    );
    try std.testing.expectError(
        error.InvalidPayload,
        checkPayload(allocator, "{\"unrelated\":true}", image),
    );
    try std.testing.expectError(error.InvalidPayload, checkPayload(
        allocator,
        \\{"critical":{"type":"cosign container image signature"}}
    ,
        image,
    ));
    try std.testing.expectError(error.InvalidPayload, checkPayload(
        allocator,
        \\{"critical":{"image":{"docker-manifest-digest":"not-a-digest"},"type":"cosign container image signature"}}
    ,
        image,
    ));
    try std.testing.expectError(error.InvalidPayload, checkPayload(
        allocator,
        \\{"critical":{"image":{"docker-manifest-digest":42},"type":"cosign container image signature"}}
    ,
        image,
    ));
    try std.testing.expectError(error.InvalidPayload, checkPayload(allocator, "", image));
}

// A real artifact, so the wire format is checked against reality and not only
// against this module's own idea of it. These are the public key, payload blob
// and signature annotation cosign published for its own v2.4.1 release image,
// `ghcr.io/sigstore/cosign/cosign`, fetched once and committed. Note that the
// payload's `docker-reference` names `gcr.io/projectsigstore/cosign` while the
// image is served from `ghcr.io` -- the concrete reason that field is ignored.

const cosign_release_public_key_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyQCx0E9wQWSFI9ULGwy3BuRklnt
    \\IqozONbbdbqz11hlRJy9c7SG+hdcFl9jE9uE/dwtuwU2MqU9T/cN0YkWww==
    \\-----END PUBLIC KEY-----
    \\
;

const cosign_release_image_digest =
    "sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31";

const cosign_release_signed_payload: SignedPayload = .{
    .payload =
    \\{"critical":{"identity":{"docker-reference":"gcr.io/projectsigstore/cosign"},"image":{"docker-manifest-digest":"sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31"},"type":"cosign container image signature"},"optional":{"GIT_HASH":"9a4cfe1aae777984c07ce373d97a65428bbff734","GIT_VERSION":"v2.4.1"}}
    ,
    .signature = "MEUCIFLs3FPY+a//a0beXlXkprM08va4Y3YKdI9nxKG9l6pmAiEAr7IU2KP4BxcRt0IQxq57MXFIEqoK8SR3Ieuo5HI488Q=",
};

test "a signature cosign itself published verifies against the key it published" {
    const key = try parsePublicKeyPem(cosign_release_public_key_pem);
    const image = try content.Digest.parse(cosign_release_image_digest);
    try verify(std.testing.allocator, cosign_release_signed_payload, key, image);

    // The payload blob is the bytes its own descriptor digest covers, and the
    // signature is over exactly those bytes.
    const blob_digest = content.digestBytes(cosign_release_signed_payload.payload);
    try std.testing.expectEqualStrings(
        "sha256:c6d2b5c70d78dc64e1cecfb3ac1deed33c4a84900c4a113cdb0a5736b718607c",
        &blob_digest.format(),
    );
}

test "the signature cosign published does not authorise a neighbouring digest" {
    const key = try parsePublicKeyPem(cosign_release_public_key_pem);
    const image = try content.Digest.parse(
        "sha256:c03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31",
    );
    try std.testing.expectError(error.PayloadImageMismatch, verify(
        std.testing.allocator,
        cosign_release_signed_payload,
        key,
        image,
    ));
}

test "the media type, annotation and payload type are the ones cosign publishes" {
    // Spelled out rather than derived, because getting any of them wrong makes
    // verification silently find nothing to verify.
    try std.testing.expectEqualStrings(
        "application/vnd.dev.cosign.simplesigning.v1+json",
        payload_media_type,
    );
    try std.testing.expectEqualStrings(
        "dev.cosignproject.cosign/signature",
        signature_annotation,
    );
    try std.testing.expectEqualStrings(
        "cosign container image signature",
        critical_type,
    );
}
