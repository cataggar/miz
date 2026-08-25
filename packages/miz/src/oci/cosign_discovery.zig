//! Finds the cosign signature artifact a registry holds for an image digest.
//!
//! This is the transport half of registry signature verification, and it
//! decides nothing. It derives the tag cosign publishes signatures under,
//! fetches what is there, and hands back the (payload, signature) pairs it
//! found. Whether any of them should be believed is `cosign.zig`'s question,
//! and whether an image with no signature may be built from is the policy's.
//! Keeping those apart is what lets the verdict be tested without a network
//! and the fetching be tested without a key.
//!
//! Discovery is by **tag** and in the **same repository**: an image digest
//! `sha256:<hex>` has its signatures at `sha256-<hex>.sig`, per the cosign
//! specification's encoding rules. The specification requires implementations
//! to support at least that mechanism, and permits signatures to live in a
//! different repository; that is not supported here, and neither is the OCI
//! 1.1 referrers API, which nothing in this package speaks yet. An image
//! signed only by a mechanism this module cannot see reads as unsigned, which
//! is exactly why "unsigned" is a distinct, named outcome rather than an
//! error a caller might mistake for a network failure.
//!
//! Nothing here is trusted before it is checked. The signature manifest's
//! digest is re-derived from its bytes, each payload blob is verified against
//! the digest and size its descriptor names before it is looked at, and the
//! payload bytes are handed on exactly as served -- the signature covers
//! those bytes, so re-serialising equivalent JSON would destroy it.

const std = @import("std");

const content = @import("content.zig");
const cosign = @import("cosign.zig");
const model = @import("model.zig");
const registry = @import("registry.zig");

const Allocator = std.mem.Allocator;

/// `sha256-` + 64 hex characters + `.sig`.
pub const signature_tag_length = "sha256-".len + 64 + ".sig".len;

/// A signature manifest with hundreds of layers is not a signed image, it is
/// an amplifier: every candidate layer costs a blob fetch. The bound is far
/// above anything cosign produces and far below anything expensive.
pub const max_candidates = 32;

/// Everything discovery can fail at that is not a transport failure. The
/// transport's own errors pass through unchanged, because a caller that has
/// to explain why a pull failed already knows how to read them.
pub const Error = error{
    /// What sits at the signature tag is not a cosign signature manifest.
    InvalidSignatureManifest,
    /// The manifest names more candidate signatures than are worth fetching.
    TooManySignatures,
    /// A payload descriptor declares a size no simple-signing payload has.
    SignaturePayloadTooLarge,
};

/// One (payload, signature) pair, owned, straight off a signature manifest and
/// verified against nothing except its own digest.
pub const Candidate = struct {
    /// The payload blob exactly as served, which is what the signature covers.
    payload: []u8,
    /// The text of the layer's `dev.cosignproject.cosign/signature`
    /// annotation, still base64.
    signature: []u8,
};

pub const Signatures = struct {
    allocator: Allocator,
    /// The tag the artifact was found under, kept so a diagnostic can say
    /// where it looked rather than making the reader derive it.
    tag: [signature_tag_length]u8,
    /// The digest of the signature manifest itself, re-derived from its bytes.
    /// Provenance names this: it is what the run actually read.
    manifest_digest: content.Digest,
    candidates: []Candidate,

    pub fn deinit(self: *Signatures) void {
        for (self.candidates) |candidate| {
            self.allocator.free(candidate.payload);
            self.allocator.free(candidate.signature);
        }
        self.allocator.free(self.candidates);
        self.* = undefined;
    }
};

/// Why an image has no signatures to check, when nothing failed.
///
/// Both arms mean "there is nothing here to verify", and they are kept apart
/// because they tell an operator different things: one says the image was
/// never signed, the other says something else is parked at the tag cosign
/// would have used.
pub const Absence = enum {
    /// The registry holds nothing at the signature tag.
    no_artifact,
    /// An artifact exists but carries no simple-signing layer with a
    /// signature annotation.
    no_signature_layer,
};

pub const Outcome = union(enum) {
    absent: Absence,
    found: Signatures,

    pub fn deinit(self: *Outcome) void {
        switch (self.*) {
            .absent => {},
            .found => |*signatures| signatures.deinit(),
        }
        self.* = undefined;
    }
};

/// The tag cosign publishes an image's signatures under.
///
/// Exactly `sha256:<hex>` to `sha256-<hex>.sig`: the algorithm separator
/// becomes a hyphen because a tag may not contain a colon, and the suffix is
/// what tells a signature apart from an attestation (`.att`) or an SBOM
/// (`.sbom`) on the same image.
pub fn signatureTag(image: content.Digest) [signature_tag_length]u8 {
    var tag: [signature_tag_length]u8 = undefined;
    @memcpy(tag[0.."sha256-".len], "sha256-");
    const hex = std.fmt.bytesToHex(image.bytes, .lower);
    @memcpy(tag["sha256-".len..][0..hex.len], &hex);
    @memcpy(tag[tag.len - ".sig".len ..], ".sig");
    return tag;
}

/// Fetches whatever signatures the registry holds for `image`.
///
/// A missing signature artifact is an ordinary answer, not a failure: the
/// registry said 404 and that is a fact about the image, so it comes back as
/// `.absent` rather than as an error a caller has to guess the meaning of.
/// Every other refusal -- an auth failure, a 500, an unreachable host --
/// stays an error, because "we could not tell" must never be reported as
/// "there is nothing there".
pub fn discover(
    source: *registry.Source,
    image: content.Digest,
) !Outcome {
    const allocator = source.allocator;
    const tag = signatureTag(image);

    var artifact = source.resolveArtifact(&tag) catch |err| switch (err) {
        error.RegistryRequestFailed => {
            const status = if (source.lastError()) |value| value.status else 0;
            if (status == 404) return .{ .absent = .no_artifact };
            return err;
        },
        else => return err,
    };
    defer artifact.deinit();

    var parsed = std.json.parseFromSlice(
        model.Manifest,
        allocator,
        artifact.bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return Error.InvalidSignatureManifest;
    defer parsed.deinit();

    var candidates: std.array_list.Managed(Candidate) = .init(allocator);
    errdefer {
        for (candidates.items) |candidate| {
            allocator.free(candidate.payload);
            allocator.free(candidate.signature);
        }
        candidates.deinit();
    }

    // A signature manifest routinely repeats one payload across several
    // layers -- cosign's own release image carries the same payload twice,
    // once signed by a key pair and once keylessly. The payload is fetched
    // once per distinct digest and copied per candidate, so a manifest cannot
    // turn a handful of signatures into a handful of downloads each.
    var fetched: std.array_list.Managed(FetchedPayload) = .init(allocator);
    defer {
        for (fetched.items) |entry| allocator.free(entry.bytes);
        fetched.deinit();
    }

    for (parsed.value.layers) |layer| {
        const media_type = layer.mediaType orelse continue;
        if (!std.mem.eql(u8, media_type, cosign.payload_media_type)) continue;
        const annotation = signatureAnnotation(layer) orelse continue;
        if (candidates.items.len == max_candidates) return Error.TooManySignatures;

        const payload = try payloadBytes(source, &fetched, layer);
        const payload_copy = try allocator.dupe(u8, payload);
        errdefer allocator.free(payload_copy);
        const signature_copy = try allocator.dupe(u8, annotation);
        errdefer allocator.free(signature_copy);
        try candidates.append(.{ .payload = payload_copy, .signature = signature_copy });
    }

    if (candidates.items.len == 0) {
        candidates.deinit();
        return .{ .absent = .no_signature_layer };
    }
    return .{ .found = .{
        .allocator = allocator,
        .tag = tag,
        .manifest_digest = artifact.digest,
        .candidates = try candidates.toOwnedSlice(),
    } };
}

const FetchedPayload = struct {
    digest: content.Digest,
    bytes: []u8,
};

fn payloadBytes(
    source: *registry.Source,
    fetched: *std.array_list.Managed(FetchedPayload),
    descriptor: model.Descriptor,
) ![]const u8 {
    if (descriptor.size > cosign.max_payload_bytes) return Error.SignaturePayloadTooLarge;
    const digest = content.Digest.parse(descriptor.digest) catch
        return Error.InvalidSignatureManifest;
    for (fetched.items) |entry| {
        if (std.mem.eql(u8, &entry.digest.bytes, &digest.bytes)) return entry.bytes;
    }
    // `readMetadata` verifies the bytes against the digest and size the
    // descriptor names before returning them, which is the check that has to
    // come first: a payload that is not the payload its manifest points at is
    // not evidence of anything.
    const bytes = try source.readMetadata(descriptor);
    errdefer source.allocator.free(bytes);
    try fetched.append(.{ .digest = digest, .bytes = bytes });
    return bytes;
}

fn signatureAnnotation(descriptor: model.Descriptor) ?[]const u8 {
    const annotations = descriptor.annotations orelse return null;
    if (annotations != .object) return null;
    const value = annotations.object.get(cosign.signature_annotation) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

test "the signature tag is the image digest with a hyphen and a suffix" {
    const image = try content.Digest.parse(
        "sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31",
    );
    const tag = signatureTag(image);
    try std.testing.expectEqualStrings(
        "sha256-b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31.sig",
        &tag,
    );
    // Every tag it produces must be a tag a registry will accept.
    try std.testing.expect(tag.len <= 128);
    for (tag) |byte| {
        try std.testing.expect(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-');
    }
}
