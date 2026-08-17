//! Native Authenticode signing support for unsigned PE/UEFI images.
//!
//! The PE parsing and range-hashing portions are adapted from ghr's
//! `src/authenticode.zig` (MIT, Copyright (c) 2026 Cameron Taggart).
//! This module deliberately contains no private-key operation: callers send
//! `PreparedRsaSha256.signing_digest` to their signing provider and supply
//! the resulting PKCS#1 v1.5 RSA signature to `finishRsaSha256Alloc`.
//!
//! It reads signatures as well as writing them, and the reading side is held
//! to the same line: `embeddedSigner`, `imageSha256` and `embeddedImageSha256`
//! say what a signature is over and who it names, never whether it is to be
//! believed. Verifying the signature itself, or a certificate chain, is a
//! trust decision and is somebody else's.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

const oid_spc_indirect_data = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04";
const oid_spc_pe_image_data = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0f";
const oid_sha256 = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
const oid_rsa_encryption = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const oid_signed_data = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
const oid_data = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
const oid_content_type = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03";
const oid_message_digest = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04";
const max_der_nesting = 32;
const max_certificate_bytes = 1024 * 1024;

const Error = error{
    InvalidPe,
    AlreadySigned,
    UnsignedPe,
    InvalidWinCertificate,
    UnsupportedWinCertificate,
    MultipleAuthenticodeSignatures,
    InvalidAuthenticodeCms,
    MissingSignerInfo,
    MultipleSignerInfos,
    UnsupportedSignerIdentifier,
    SignerCertificateNotFound,
    AmbiguousSignerCertificate,
    FileTooLarge,
    InvalidDer,
    InvalidCertificate,
    InvalidCertificatePem,
    InvalidSignatureLength,
    UnsupportedSignatureDigestAlgorithm,
    TrailingDataAfterCertificateTable,
};

/// A SHA-256 digest, the only image digest this module produces or reads.
pub const Digest = [Sha256.digest_length]u8;

const Pe = struct {
    machine: u16,
    checksum_offset: usize,
    security_directory_offset: usize,
    certificate_offset: usize,
    certificate_size: usize,
};

/// Signer selected from an existing PE's Authenticode CMS `SignerInfo`.
/// Every slice borrows from the PE passed to `embeddedSigner`.
pub const EmbeddedSigner = struct {
    machine: u16,
    certificate_der: []const u8,
    subject_der: []const u8,
    issuer_der: []const u8,
    serial_number: []const u8,
};

/// Values passed between the external signing operation and CMS construction.
pub const PreparedRsaSha256 = struct {
    aligned_pe: []u8,
    spc_indirect_data: []u8,
    signed_attributes: []u8,
    signing_digest: [32]u8,

    pub fn deinit(self: *PreparedRsaSha256, allocator: std.mem.Allocator) void {
        allocator.free(self.aligned_pe);
        allocator.free(self.spc_indirect_data);
        allocator.free(self.signed_attributes);
        self.* = undefined;
    }
};

/// X.509 certificates extracted from an Artifact Signing CMS certchain body.
pub const ArtifactSigningCertificateChain = struct {
    certificates: [][]u8,

    pub fn deinit(self: *ArtifactSigningCertificateChain, allocator: std.mem.Allocator) void {
        for (self.certificates) |certificate| allocator.free(certificate);
        allocator.free(self.certificates);
        self.* = undefined;
    }
};

const ArtifactSigningCms = struct {
    encap_content_info: DerElement,
    certificates: DerElement,
};

/// Parses the binary application/pkcs7-mime response from `/sign/certchain`.
pub fn parseArtifactSigningCertificateChainAlloc(
    allocator: std.mem.Allocator,
    body: []const u8,
) !ArtifactSigningCertificateChain {
    const cms = try parseArtifactSigningCms(body);
    const certificates = cms.certificates;

    var result = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (result.items) |certificate| allocator.free(certificate);
        result.deinit();
    }
    var index = certificates.content_start;
    while (index < certificates.end) {
        const certificate = try parseDerElement(body, index);
        if (certificate.tag != 0x30) return error.InvalidCertificate;
        _ = try extractIssuerAndSerial(body[certificate.start..certificate.end]);
        for (result.items) |existing| {
            if (std.mem.eql(u8, existing, body[certificate.start..certificate.end]))
                return error.InvalidCertificate;
        }
        try result.append(try allocator.dupe(u8, body[certificate.start..certificate.end]));
        index = certificate.end;
    }
    if (index != certificates.end or result.items.len == 0) return error.InvalidDer;
    return .{ .certificates = try result.toOwnedSlice() };
}

/// Returns the leaf certificate carried as the encapsulated content of an
/// Artifact Signing certificate bundle.
pub fn artifactSigningCertificateDer(body: []const u8) ![]const u8 {
    const cms = try parseArtifactSigningCms(body);
    var index = cms.encap_content_info.content_start;
    const content_type = try parseDerElement(body, index);
    if (content_type.tag != 0x06 or
        !std.mem.eql(u8, body[content_type.start..content_type.end], oid_data))
    {
        return error.InvalidDer;
    }
    index = content_type.end;
    const explicit_content = try parseDerElement(body, index);
    if (explicit_content.tag != 0xa0 or
        explicit_content.end != cms.encap_content_info.end)
    {
        return error.InvalidDer;
    }
    const octet_string = try parseDerElement(body, explicit_content.content_start);
    if (octet_string.tag != 0x04 or octet_string.end != explicit_content.end)
        return error.InvalidDer;
    const certificate_der = body[octet_string.content_start..octet_string.end];
    const certificate = try parseDerElement(certificate_der, 0);
    if (certificate.tag != 0x30 or certificate.end != certificate_der.len)
        return error.InvalidCertificate;
    _ = try extractIssuerAndSerial(certificate_der);

    index = cms.certificates.content_start;
    while (index < cms.certificates.end) {
        const bundled = try parseDerElement(body, index);
        if (std.mem.eql(
            u8,
            body[bundled.start..bundled.end],
            certificate_der,
        )) {
            return certificate_der;
        }
        index = bundled.end;
    }
    return error.InvalidCertificate;
}

pub fn validateX509CertificateDer(certificate_der: []const u8) !void {
    const certificate = try parseDerElement(certificate_der, 0);
    if (certificate.tag != 0x30 or certificate.end != certificate_der.len)
        return error.InvalidCertificate;
    try validateDerTree(certificate_der, certificate, 0);
    _ = try extractIssuerAndSerial(certificate_der);
}

/// Identifies the certificate referenced by an existing PE's Authenticode
/// `SignerInfo`. This validates structure and identity binding, not the
/// cryptographic signature or certificate chain.
pub fn embeddedSigner(pe_bytes: []const u8) !EmbeddedSigner {
    const table = try authenticodeCms(pe_bytes);
    return parseAuthenticodeCms(table.machine, table.cms);
}

/// The SHA-256 an Authenticode signature covers, computed from the image
/// itself. The PE checksum, the security data directory entry and the
/// certificate table are excluded, which is what makes a signed image's digest
/// equal to that of the unsigned image it was made from.
pub fn imageSha256(pe_bytes: []const u8) Error!Digest {
    const pe = try parsePe(pe_bytes);
    const end = if (pe.certificate_offset == 0 and pe.certificate_size == 0)
        pe_bytes.len
    else blk: {
        const table = try certificateTableRange(pe_bytes, pe);
        // The table is the last thing in the file. Anything after it would be
        // outside both the signature and the loader's view of the image, so it
        // is refused rather than hashed on a guess about which side it is on.
        if (table.end != pe_bytes.len) return error.TrailingDataAfterCertificateTable;
        break :blk table.start;
    };
    var digest: Digest = undefined;
    var hash = Sha256.init(.{});
    hash.update(pe_bytes[0..pe.checksum_offset]);
    hash.update(pe_bytes[pe.checksum_offset + 4 .. pe.security_directory_offset]);
    hash.update(pe_bytes[pe.security_directory_offset + 8 .. end]);
    hash.final(&digest);
    return digest;
}

/// The image digest an existing signature claims to cover, read out of the
/// CMS `SpcIndirectDataContent` rather than recomputed. Comparing it with
/// `imageSha256` is what separates "a signature is attached" from "the
/// signature commits to these bytes"; it is still not a trust decision, since
/// no signature, key or certificate chain is verified.
pub fn embeddedImageSha256(pe_bytes: []const u8) Error!Digest {
    const table = try authenticodeCms(pe_bytes);
    const body = table.cms;
    const spc = try spcIndirectDataContent(body);
    // SpcIndirectDataContent ::= SEQUENCE { data ANY, messageDigest DigestInfo }
    const data = try parseDerElement(body, spc.content_start);
    const digest_info = try parseDerElement(body, data.end);
    if (digest_info.tag != 0x30 or digest_info.end != spc.end) return error.InvalidDer;
    const algorithm = try parseDerElement(body, digest_info.content_start);
    if (algorithm.tag != 0x30) return error.InvalidDer;
    const algorithm_oid = try parseDerElement(body, algorithm.content_start);
    if (algorithm_oid.tag != 0x06) return error.InvalidDer;
    if (!std.mem.eql(u8, body[algorithm_oid.start..algorithm_oid.end], oid_sha256))
        return error.UnsupportedSignatureDigestAlgorithm;
    const digest_value = try parseDerElement(body, algorithm.end);
    if (digest_value.tag != 0x04 or digest_value.end != digest_info.end)
        return error.InvalidDer;
    const bytes = body[digest_value.content_start..digest_value.end];
    if (bytes.len != Sha256.digest_length) return error.UnsupportedSignatureDigestAlgorithm;
    var digest: Digest = undefined;
    @memcpy(&digest, bytes);
    return digest;
}

const CertificateTableRange = struct {
    start: usize,
    end: usize,
};

fn certificateTableRange(pe_bytes: []const u8, pe: Pe) Error!CertificateTableRange {
    if (pe.certificate_offset == 0 or pe.certificate_size == 0 or
        pe.certificate_offset % 8 != 0)
    {
        return error.InvalidWinCertificate;
    }
    if (pe.certificate_offset < pe.security_directory_offset + 8)
        return error.InvalidWinCertificate;
    const end = std.math.add(
        usize,
        pe.certificate_offset,
        pe.certificate_size,
    ) catch return error.InvalidWinCertificate;
    if (end > pe_bytes.len) return error.InvalidWinCertificate;
    return .{ .start = pe.certificate_offset, .end = end };
}

const AuthenticodeCms = struct {
    machine: u16,
    cms: []const u8,
};

/// The single WIN_CERTIFICATE entry's CMS body. More than one Authenticode
/// signature, or an entry of any other type, is refused rather than picked
/// between.
fn authenticodeCms(pe_bytes: []const u8) Error!AuthenticodeCms {
    const pe = try parsePe(pe_bytes);
    if (pe.certificate_offset == 0 and pe.certificate_size == 0)
        return error.UnsignedPe;
    const table = try certificateTableRange(pe_bytes, pe);

    var result: ?[]const u8 = null;
    var offset = table.start;
    while (offset < table.end) {
        const header_end = std.math.add(usize, offset, 8) catch
            return error.InvalidWinCertificate;
        if (header_end > table.end) return error.InvalidWinCertificate;
        const entry_length = @as(usize, readU32Le(pe_bytes[offset..][0..4]));
        if (entry_length < 8) return error.InvalidWinCertificate;
        const entry_end = std.math.add(usize, offset, entry_length) catch
            return error.InvalidWinCertificate;
        if (entry_end > table.end) return error.InvalidWinCertificate;
        if (readU16Le(pe_bytes[offset + 4 ..][0..2]) != 0x0200 or
            readU16Le(pe_bytes[offset + 6 ..][0..2]) != 0x0002)
        {
            return error.UnsupportedWinCertificate;
        }
        if (result != null) return error.MultipleAuthenticodeSignatures;
        result = pe_bytes[offset + 8 .. entry_end];

        const next = align8(entry_end) catch return error.InvalidWinCertificate;
        if (next > table.end) return error.InvalidWinCertificate;
        for (pe_bytes[entry_end..next]) |padding| {
            if (padding != 0) return error.InvalidWinCertificate;
        }
        offset = next;
    }
    if (offset != table.end) return error.InvalidWinCertificate;
    return .{
        .machine = pe.machine,
        .cms = result orelse return error.UnsignedPe,
    };
}

/// Navigates a CMS `SignedData` to its encapsulated
/// `SpcIndirectDataContent`, which is where an Authenticode signature states
/// what it covers.
fn spcIndirectDataContent(body: []const u8) Error!DerElement {
    const content_info = try parseDerElement(body, 0);
    if (content_info.tag != 0x30 or content_info.end != body.len)
        return error.InvalidDer;
    try validateDerTree(body, content_info, 0);

    var index = content_info.content_start;
    const content_type = try parseDerElement(body, index);
    if (content_type.tag != 0x06 or
        !std.mem.eql(u8, body[content_type.start..content_type.end], oid_signed_data))
    {
        return error.InvalidDer;
    }
    index = content_type.end;
    const signed_data_explicit = try parseDerElement(body, index);
    if (signed_data_explicit.tag != 0xa0 or
        signed_data_explicit.end != content_info.end)
    {
        return error.InvalidDer;
    }
    const signed_data = try parseDerElement(body, signed_data_explicit.content_start);
    if (signed_data.tag != 0x30 or signed_data.end != signed_data_explicit.end)
        return error.InvalidDer;

    index = signed_data.content_start;
    const version = try parseDerElement(body, index);
    if (version.tag != 0x02) return error.InvalidDer;
    index = version.end;
    const digest_algorithms = try parseDerElement(body, index);
    if (digest_algorithms.tag != 0x31) return error.InvalidDer;
    index = digest_algorithms.end;
    const encap_content_info = try parseDerElement(body, index);
    if (encap_content_info.tag != 0x30) return error.InvalidDer;

    const encap_index = encap_content_info.content_start;
    const encap_content_type = try parseDerElement(body, encap_index);
    if (encap_content_type.tag != 0x06 or
        !std.mem.eql(
            u8,
            body[encap_content_type.start..encap_content_type.end],
            oid_spc_indirect_data,
        ))
    {
        return error.InvalidDer;
    }
    const explicit = try parseDerElement(body, encap_content_type.end);
    if (explicit.tag != 0xa0 or explicit.end != encap_content_info.end)
        return error.InvalidDer;
    const spc = try parseDerElement(body, explicit.content_start);
    if (spc.tag != 0x30 or spc.end != explicit.end) return error.InvalidDer;
    return spc;
}

pub fn decodePemCertificateAlloc(
    allocator: std.mem.Allocator,
    pem: []const u8,
) ![]u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse
        return error.InvalidCertificatePem;
    if (std.mem.trim(u8, pem[0..begin], " \t\r\n").len != 0)
        return error.InvalidCertificatePem;
    const body_start = begin + begin_marker.len;
    const relative_end = std.mem.indexOf(
        u8,
        pem[body_start..],
        end_marker,
    ) orelse return error.InvalidCertificatePem;
    const body_end = body_start + relative_end;
    const suffix = pem[body_end + end_marker.len ..];
    if (std.mem.trim(u8, suffix, " \t\r\n").len != 0)
        return error.InvalidCertificatePem;

    var encoded: std.Io.Writer.Allocating = .init(allocator);
    defer encoded.deinit();
    for (pem[body_start..body_end]) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        try encoded.writer.writeByte(byte);
    }
    const encoded_slice = encoded.written();
    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(
        encoded_slice,
    ) catch return error.InvalidCertificatePem;
    if (decoded_size == 0 or decoded_size > max_certificate_bytes)
        return error.InvalidCertificatePem;
    const certificate = try allocator.alloc(u8, decoded_size);
    errdefer allocator.free(certificate);
    std.base64.standard.Decoder.decode(certificate, encoded_slice) catch
        return error.InvalidCertificatePem;
    try validateX509CertificateDer(certificate);
    return certificate;
}

pub fn encodePemCertificateAlloc(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) ![]u8 {
    if (certificate_der.len == 0 or
        certificate_der.len > max_certificate_bytes)
    {
        return error.InvalidCertificate;
    }
    try validateX509CertificateDer(certificate_der);
    const encoded = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(certificate_der.len),
    );
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, certificate_der);

    var pem: std.Io.Writer.Allocating = .init(allocator);
    errdefer pem.deinit();
    try pem.writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    var offset: usize = 0;
    while (offset < encoded.len) {
        const end = @min(offset + 64, encoded.len);
        try pem.writer.writeAll(encoded[offset..end]);
        try pem.writer.writeByte('\n');
        offset = end;
    }
    try pem.writer.writeAll("-----END CERTIFICATE-----\n");
    return pem.toOwnedSlice();
}

fn parseAuthenticodeCms(machine: u16, body: []const u8) Error!EmbeddedSigner {
    return parseAuthenticodeCmsInner(machine, body) catch |err| switch (err) {
        error.MissingSignerInfo,
        error.MultipleSignerInfos,
        error.UnsupportedSignerIdentifier,
        error.SignerCertificateNotFound,
        error.AmbiguousSignerCertificate,
        => err,
        else => error.InvalidAuthenticodeCms,
    };
}

fn parseAuthenticodeCmsInner(
    machine: u16,
    body: []const u8,
) Error!EmbeddedSigner {
    const content_info = try parseDerElement(body, 0);
    if (content_info.tag != 0x30 or content_info.end != body.len)
        return error.InvalidDer;
    try validateDerTree(body, content_info, 0);

    var index = content_info.content_start;
    const content_type = try parseDerElement(body, index);
    if (content_type.tag != 0x06 or
        !std.mem.eql(
            u8,
            body[content_type.start..content_type.end],
            oid_signed_data,
        ))
    {
        return error.InvalidDer;
    }
    index = content_type.end;
    const signed_data_explicit = try parseDerElement(body, index);
    if (signed_data_explicit.tag != 0xa0 or
        signed_data_explicit.end != content_info.end)
    {
        return error.InvalidDer;
    }
    const signed_data = try parseDerElement(
        body,
        signed_data_explicit.content_start,
    );
    if (signed_data.tag != 0x30 or
        signed_data.end != signed_data_explicit.end)
    {
        return error.InvalidDer;
    }

    index = signed_data.content_start;
    const version = try parseDerElement(body, index);
    if (version.tag != 0x02 or version.content_start == version.end)
        return error.InvalidDer;
    index = version.end;
    const digest_algorithms = try parseDerElement(body, index);
    if (digest_algorithms.tag != 0x31) return error.InvalidDer;
    index = digest_algorithms.end;
    const encap_content_info = try parseDerElement(body, index);
    if (encap_content_info.tag != 0x30) return error.InvalidDer;
    var encap_index = encap_content_info.content_start;
    const encap_content_type = try parseDerElement(body, encap_index);
    if (encap_content_type.tag != 0x06 or
        !std.mem.eql(
            u8,
            body[encap_content_type.start..encap_content_type.end],
            oid_spc_indirect_data,
        ))
    {
        return error.InvalidDer;
    }
    encap_index = encap_content_type.end;
    while (encap_index < encap_content_info.end) {
        encap_index = (try parseDerElement(body, encap_index)).end;
    }
    if (encap_index != encap_content_info.end) return error.InvalidDer;
    index = encap_content_info.end;

    const certificates = try parseDerElement(body, index);
    if (certificates.tag != 0xa0 or
        certificates.content_start == certificates.end)
    {
        return error.InvalidDer;
    }
    index = certificates.end;
    if (index < signed_data.end) {
        const possible_crls = try parseDerElement(body, index);
        if (possible_crls.tag == 0xa1) index = possible_crls.end;
    }
    const signer_infos = try parseDerElement(body, index);
    if (signer_infos.tag != 0x31 or signer_infos.end != signed_data.end)
        return error.InvalidDer;

    var signer_index = signer_infos.content_start;
    if (signer_index == signer_infos.end) return error.MissingSignerInfo;
    const signer_info = try parseDerElement(body, signer_index);
    if (signer_info.tag != 0x30) return error.InvalidDer;
    signer_index = signer_info.end;
    if (signer_index != signer_infos.end) return error.MultipleSignerInfos;

    var field_index = signer_info.content_start;
    const signer_version = try parseDerElement(body, field_index);
    if (signer_version.tag != 0x02 or
        signer_version.content_start == signer_version.end)
    {
        return error.InvalidDer;
    }
    field_index = signer_version.end;
    const signer_identifier = try parseDerElement(body, field_index);
    if (signer_identifier.tag != 0x30)
        return error.UnsupportedSignerIdentifier;
    var sid_index = signer_identifier.content_start;
    const sid_issuer = try parseDerElement(body, sid_index);
    if (sid_issuer.tag != 0x30) return error.InvalidDer;
    sid_index = sid_issuer.end;
    const sid_serial = try parseDerElement(body, sid_index);
    if (sid_serial.tag != 0x02 or sid_serial.content_start == sid_serial.end)
        return error.InvalidDer;
    sid_index = sid_serial.end;
    if (sid_index != signer_identifier.end) return error.InvalidDer;

    field_index = signer_identifier.end;
    const digest_algorithm = try parseDerElement(body, field_index);
    if (digest_algorithm.tag != 0x30) return error.InvalidDer;
    field_index = digest_algorithm.end;
    var field = try parseDerElement(body, field_index);
    if (field.tag == 0xa0) {
        field_index = field.end;
        field = try parseDerElement(body, field_index);
    }
    if (field.tag != 0x30) return error.InvalidDer;
    field_index = field.end;
    const signature = try parseDerElement(body, field_index);
    if (signature.tag != 0x04 or signature.content_start == signature.end)
        return error.InvalidDer;
    field_index = signature.end;
    if (field_index < signer_info.end) {
        const unsigned_attributes = try parseDerElement(body, field_index);
        if (unsigned_attributes.tag != 0xa1) return error.InvalidDer;
        field_index = unsigned_attributes.end;
    }
    if (field_index != signer_info.end) return error.InvalidDer;

    var match: ?EmbeddedSigner = null;
    var certificate_index = certificates.content_start;
    while (certificate_index < certificates.end) {
        const certificate = try parseDerElement(body, certificate_index);
        if (certificate.tag != 0x30) return error.InvalidCertificate;
        const certificate_der = body[certificate.start..certificate.end];
        const identity = try extractIssuerAndSerial(certificate_der);
        if (std.mem.eql(
            u8,
            identity.issuer,
            body[sid_issuer.start..sid_issuer.end],
        ) and std.mem.eql(
            u8,
            identity.serial,
            body[sid_serial.start..sid_serial.end],
        )) {
            if (match != null) return error.AmbiguousSignerCertificate;
            match = .{
                .machine = machine,
                .certificate_der = certificate_der,
                .subject_der = identity.subject,
                .issuer_der = identity.issuer,
                .serial_number = identity.serial_number,
            };
        }
        certificate_index = certificate.end;
    }
    if (certificate_index != certificates.end) return error.InvalidDer;
    return match orelse error.SignerCertificateNotFound;
}

fn parseArtifactSigningCms(body: []const u8) !ArtifactSigningCms {
    const content_info = try parseDerElement(body, 0);
    if (content_info.tag != 0x30 or content_info.end != body.len) return error.InvalidDer;
    try validateDerTree(body, content_info, 0);

    var index = content_info.content_start;
    const content_type = try parseDerElement(body, index);
    if (content_type.tag != 0x06 or !std.mem.eql(u8, body[content_type.start..content_type.end], oid_signed_data))
        return error.InvalidDer;
    index = content_type.end;
    const signed_data_explicit = try parseDerElement(body, index);
    if (signed_data_explicit.tag != 0xa0) return error.InvalidDer;
    const signed_data = try parseDerElement(body, signed_data_explicit.content_start);
    if (signed_data.tag != 0x30 or signed_data.end != signed_data_explicit.end) return error.InvalidDer;
    if (signed_data_explicit.end != content_info.end) return error.InvalidDer;

    index = signed_data.content_start;
    const version = try parseDerElement(body, index);
    if (version.tag != 0x02 or version.content_start == version.end) return error.InvalidDer;
    index = version.end;
    const digest_algorithms = try parseDerElement(body, index);
    if (digest_algorithms.tag != 0x31) return error.InvalidDer;
    index = digest_algorithms.end;
    const encap_content_info = try parseDerElement(body, index);
    if (encap_content_info.tag != 0x30) return error.InvalidDer;
    index = encap_content_info.end;
    const certificates = try parseDerElement(body, index);
    if (certificates.tag != 0xa0 or certificates.content_start == certificates.end) return error.InvalidDer;
    index = certificates.end;
    const signer_infos = try parseDerElement(body, index);
    if (signer_infos.tag != 0x31 or signer_infos.end != signed_data.end) return error.InvalidDer;
    return .{
        .encap_content_info = encap_content_info,
        .certificates = certificates,
    };
}

/// Prepares an unsigned PE image for external RSA/SHA-256 signing.
pub fn prepareRsaSha256Alloc(
    allocator: std.mem.Allocator,
    unsigned_pe: []const u8,
) !PreparedRsaSha256 {
    try requireU32Size(unsigned_pe.len);
    const aligned_len = try align8(unsigned_pe.len);
    try requireU32Size(aligned_len);

    var aligned_pe = try allocator.alloc(u8, aligned_len);
    errdefer allocator.free(aligned_pe);
    @memcpy(aligned_pe[0..unsigned_pe.len], unsigned_pe);
    @memset(aligned_pe[unsigned_pe.len..], 0);

    const pe = try parseUnsignedPe(aligned_pe);
    var pe_digest: [Sha256.digest_length]u8 = undefined;
    hashPe(aligned_pe, pe, &pe_digest);

    const spc_indirect_data = try makeSpcIndirectData(allocator, pe_digest);
    errdefer allocator.free(spc_indirect_data);

    const signed_attributes = try makeSignedAttributes(allocator, spc_indirect_data);
    errdefer allocator.free(signed_attributes);

    var signing_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(signed_attributes, &signing_digest, .{});
    return .{
        .aligned_pe = aligned_pe,
        .spc_indirect_data = spc_indirect_data,
        .signed_attributes = signed_attributes,
        .signing_digest = signing_digest,
    };
}

/// Embeds a provider-produced PKCS#1 v1.5 RSA/SHA-256 signature in a CMS
/// Authenticode certificate table. Ownership of `prepared` stays with caller.
pub fn finishRsaSha256Alloc(
    allocator: std.mem.Allocator,
    prepared: PreparedRsaSha256,
    certificate_der: []const u8,
    rsa_signature: []const u8,
) ![]u8 {
    return finishRsaSha256WithChainAlloc(allocator, prepared, certificate_der, &.{}, rsa_signature);
}

/// Embeds an RSA/SHA-256 signature and X.509 certificate chain, omitting
/// self-issued roots that verifiers must obtain from their trust store.
/// Ownership of `prepared` stays with caller.
pub fn finishRsaSha256WithChainAlloc(
    allocator: std.mem.Allocator,
    prepared: PreparedRsaSha256,
    signing_certificate_der: []const u8,
    certificate_chain: []const []const u8,
    rsa_signature: []const u8,
) ![]u8 {
    if (!validRsaSignatureLength(rsa_signature.len)) return error.InvalidSignatureLength;
    const pe = try parseUnsignedPe(prepared.aligned_pe);
    const issuer_and_serial = try extractIssuerAndSerial(signing_certificate_der);
    const certificate_set = try makeCertificateSet(allocator, signing_certificate_der, certificate_chain);
    defer allocator.free(certificate_set);
    const cms = try makeCms(
        allocator,
        prepared.spc_indirect_data,
        prepared.signed_attributes,
        certificate_set,
        issuer_and_serial,
        rsa_signature,
    );
    defer allocator.free(cms);

    const certificate_length = try std.math.add(usize, 8, cms.len);
    try requireU32Size(certificate_length);
    const certificate_table_size = try align8(certificate_length);
    try requireU32Size(certificate_table_size);
    const output_len = try std.math.add(usize, prepared.aligned_pe.len, certificate_table_size);
    try requireU32Size(output_len);

    var output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    @memcpy(output[0..prepared.aligned_pe.len], prepared.aligned_pe);
    @memset(output[prepared.aligned_pe.len..], 0);

    writeU32Le(output[pe.security_directory_offset..][0..4], try asU32(prepared.aligned_pe.len));
    writeU32Le(output[pe.security_directory_offset + 4 ..][0..4], try asU32(certificate_table_size));
    const certificate_offset = prepared.aligned_pe.len;
    writeU32Le(output[certificate_offset..][0..4], try asU32(certificate_length));
    writeU16Le(output[certificate_offset + 4 ..][0..2], 0x0200);
    writeU16Le(output[certificate_offset + 6 ..][0..2], 0x0002);
    @memcpy(output[certificate_offset + 8 .. certificate_offset + certificate_length], cms);
    return output;
}

fn parseUnsignedPe(bytes: []const u8) Error!Pe {
    const pe = try parsePe(bytes);
    if (pe.certificate_offset != 0 or pe.certificate_size != 0)
        return error.AlreadySigned;
    return pe;
}

fn parsePe(bytes: []const u8) Error!Pe {
    try requireU32Size(bytes.len);
    if (bytes.len < 0x40 or !std.mem.eql(u8, bytes[0..2], "MZ")) return error.InvalidPe;
    const nt_offset = @as(usize, readU32Le(bytes[0x3c..][0..4]));
    if (nt_offset < 0x40) return error.InvalidPe;
    const nt_end = std.math.add(usize, nt_offset, 4) catch return error.InvalidPe;
    if (nt_end > bytes.len or !std.mem.eql(u8, bytes[nt_offset..nt_end], "PE\x00\x00"))
        return error.InvalidPe;

    const file_header_offset = nt_end;
    const file_header_end = std.math.add(usize, file_header_offset, 20) catch return error.InvalidPe;
    if (file_header_end > bytes.len) return error.InvalidPe;
    const optional_size = @as(usize, readU16Le(bytes[file_header_offset + 16 ..][0..2]));
    const optional_offset = file_header_end;
    const optional_end = std.math.add(usize, optional_offset, optional_size) catch return error.InvalidPe;
    if (optional_end > bytes.len) return error.InvalidPe;

    const magic_end = std.math.add(usize, optional_offset, 2) catch return error.InvalidPe;
    if (magic_end > optional_end) return error.InvalidPe;
    const magic = readU16Le(bytes[optional_offset..][0..2]);
    const data_directory_relative_offset: usize = switch (magic) {
        0x10b => 96,
        0x20b => 112,
        else => return error.InvalidPe,
    };
    const checksum_offset = std.math.add(usize, optional_offset, 64) catch return error.InvalidPe;
    const checksum_end = std.math.add(usize, checksum_offset, 4) catch return error.InvalidPe;
    if (checksum_end > optional_end) return error.InvalidPe;

    const count_offset = std.math.add(usize, optional_offset, data_directory_relative_offset - 4) catch return error.InvalidPe;
    const count_end = std.math.add(usize, count_offset, 4) catch return error.InvalidPe;
    if (count_end > optional_end) return error.InvalidPe;
    if (readU32Le(bytes[count_offset..][0..4]) < 5) return error.InvalidPe;

    const security_directory_offset = std.math.add(
        usize,
        optional_offset,
        data_directory_relative_offset + 4 * 8,
    ) catch return error.InvalidPe;
    const security_directory_end = std.math.add(usize, security_directory_offset, 8) catch return error.InvalidPe;
    if (security_directory_end > optional_end) return error.InvalidPe;
    const certificate_offset = readU32Le(bytes[security_directory_offset..][0..4]);
    const certificate_size = readU32Le(bytes[security_directory_offset + 4 ..][0..4]);
    return .{
        .machine = readU16Le(bytes[file_header_offset..][0..2]),
        .checksum_offset = checksum_offset,
        .security_directory_offset = security_directory_offset,
        .certificate_offset = certificate_offset,
        .certificate_size = certificate_size,
    };
}

fn hashPe(bytes: []const u8, pe: Pe, digest: *[Sha256.digest_length]u8) void {
    var hash = Sha256.init(.{});
    hash.update(bytes[0..pe.checksum_offset]);
    hash.update(bytes[pe.checksum_offset + 4 .. pe.security_directory_offset]);
    hash.update(bytes[pe.security_directory_offset + 8 ..]);
    hash.final(digest);
}

fn makeSpcIndirectData(allocator: std.mem.Allocator, pe_digest: [32]u8) ![]u8 {
    var data = std.array_list.Managed(u8).init(allocator);
    defer data.deinit();
    try data.appendSlice("\x30\x33");
    try data.appendSlice(oid_spc_pe_image_data);
    try data.appendSlice("\x30\x25\x03\x01\x00\xa0\x20\xa2\x1e\x80\x1c");
    try data.appendSlice(
        "\x00\x3c\x00\x3c\x00\x3c\x00\x4f\x00\x62\x00\x73\x00\x6f\x00\x6c" ++
            "\x00\x65\x00\x74\x00\x65\x00\x3e\x00\x3e\x00\x3e",
    );

    const digest_algorithm = try algorithmIdentifier(allocator, oid_sha256);
    defer allocator.free(digest_algorithm);
    var digest_info = std.array_list.Managed(u8).init(allocator);
    defer digest_info.deinit();
    try digest_info.appendSlice(digest_algorithm);
    try appendDer(&digest_info, 0x04, &pe_digest);

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try body.appendSlice(data.items);
    try appendDer(&body, 0x30, digest_info.items);
    return wrapDer(allocator, 0x30, body.items);
}

fn makeSignedAttributes(allocator: std.mem.Allocator, spc: []const u8) ![]u8 {
    if (spc.len < 2 or spc[0] != 0x30) return error.InvalidDer;
    const spc_element = try parseDerElement(spc, 0);
    if (spc_element.end != spc.len) return error.InvalidDer;
    var content_type_value = std.array_list.Managed(u8).init(allocator);
    defer content_type_value.deinit();
    try content_type_value.appendSlice(oid_spc_indirect_data);
    const content_type_set = try wrapDer(allocator, 0x31, content_type_value.items);
    defer allocator.free(content_type_set);
    const content_type_attribute = try makeAttribute(allocator, oid_content_type, content_type_set);
    defer allocator.free(content_type_attribute);

    var message_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(spc[spc_element.content_start..spc_element.end], &message_digest, .{});
    const digest_value = try wrapDer(allocator, 0x04, &message_digest);
    defer allocator.free(digest_value);
    const digest_set = try wrapDer(allocator, 0x31, digest_value);
    defer allocator.free(digest_set);
    const digest_attribute = try makeAttribute(allocator, oid_message_digest, digest_set);
    defer allocator.free(digest_attribute);

    var set_body = std.array_list.Managed(u8).init(allocator);
    defer set_body.deinit();
    if (std.mem.order(u8, content_type_attribute, digest_attribute) == .gt) {
        try set_body.appendSlice(digest_attribute);
        try set_body.appendSlice(content_type_attribute);
    } else {
        try set_body.appendSlice(content_type_attribute);
        try set_body.appendSlice(digest_attribute);
    }
    return wrapDer(allocator, 0x31, set_body.items);
}

fn makeAttribute(allocator: std.mem.Allocator, oid: []const u8, value_set: []const u8) ![]u8 {
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try body.appendSlice(oid);
    try body.appendSlice(value_set);
    return wrapDer(allocator, 0x30, body.items);
}

const IssuerAndSerial = struct {
    issuer: []const u8,
    subject: []const u8,
    serial: []const u8,
    serial_number: []const u8,
};

fn makeCertificateSet(
    allocator: std.mem.Allocator,
    signing_certificate: []const u8,
    certificate_chain: []const []const u8,
) ![]u8 {
    const certificate_count = std.math.add(usize, certificate_chain.len, 1) catch return error.FileTooLarge;
    const all_certificates = try allocator.alloc([]const u8, certificate_count);
    defer allocator.free(all_certificates);
    all_certificates[0] = signing_certificate;
    @memcpy(all_certificates[1..], certificate_chain);

    var unique_count: usize = 0;
    for (all_certificates) |certificate| {
        const identity = try extractIssuerAndSerial(certificate);
        if (!std.mem.eql(u8, certificate, signing_certificate) and
            std.mem.eql(u8, identity.issuer, identity.subject))
        {
            continue;
        }
        var duplicate = false;
        for (all_certificates[0..unique_count]) |existing| {
            if (std.mem.eql(u8, certificate, existing)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            all_certificates[unique_count] = certificate;
            unique_count += 1;
        }
    }

    var i: usize = 1;
    while (i < unique_count) : (i += 1) {
        const certificate = all_certificates[i];
        var position = i;
        while (position > 0 and std.mem.order(u8, certificate, all_certificates[position - 1]) == .lt) {
            all_certificates[position] = all_certificates[position - 1];
            position -= 1;
        }
        all_certificates[position] = certificate;
    }

    var result = std.array_list.Managed(u8).init(allocator);
    defer result.deinit();
    for (all_certificates[0..unique_count]) |certificate| try result.appendSlice(certificate);
    return result.toOwnedSlice();
}

fn extractIssuerAndSerial(certificate: []const u8) Error!IssuerAndSerial {
    try requireU32Size(certificate.len);
    const outer = try parseCertificateElement(certificate, 0);
    if (outer.tag != 0x30 or outer.end != certificate.len) return error.InvalidCertificate;
    try validateCertificateDer(certificate, outer);
    const tbs = try parseCertificateElement(certificate, outer.content_start);
    if (tbs.tag != 0x30 or tbs.end > outer.end) return error.InvalidCertificate;
    var index = tbs.content_start;
    var field = try parseCertificateElement(certificate, index);
    if (field.tag == 0xa0) {
        const version = try parseCertificateElement(certificate, field.content_start);
        if (version.tag != 0x02 or version.end != field.end) return error.InvalidCertificate;
        index = field.end;
        field = try parseCertificateElement(certificate, index);
    }
    if (field.tag != 0x02 or field.content_start == field.end) return error.InvalidCertificate;
    const serial = certificate[field.start..field.end];
    if (certificate[field.content_start] & 0x80 != 0)
        return error.InvalidCertificate;
    index = field.end;
    const signature_algorithm = try parseCertificateElement(certificate, index);
    try validateAlgorithmIdentifier(certificate, signature_algorithm);
    index = signature_algorithm.end;
    const issuer_field = try parseCertificateElement(certificate, index);
    try validateName(certificate, issuer_field, false);
    const issuer = certificate[issuer_field.start..issuer_field.end];

    index = issuer_field.end;
    const validity_field = try parseCertificateElement(certificate, index);
    try validateValidity(certificate, validity_field);
    index = validity_field.end;
    const subject_field = try parseCertificateElement(certificate, index);
    try validateName(certificate, subject_field, true);
    const subject = certificate[subject_field.start..subject_field.end];

    index = subject_field.end;
    const subject_public_key_info = try parseCertificateElement(
        certificate,
        index,
    );
    try validateSubjectPublicKeyInfo(certificate, subject_public_key_info);
    index = subject_public_key_info.end;
    var last_optional_tag: u8 = 0x80;
    while (index < tbs.end) {
        const optional = try parseCertificateElement(certificate, index);
        if (optional.tag <= last_optional_tag) return error.InvalidCertificate;
        switch (optional.tag) {
            0x81, 0x82 => try validateBitStringContent(
                certificate[optional.content_start..optional.end],
            ),
            0xa3 => try validateExtensions(certificate, optional),
            else => return error.InvalidCertificate,
        }
        last_optional_tag = optional.tag;
        index = optional.end;
    }
    if (index != tbs.end) return error.InvalidCertificate;
    index = tbs.end;
    const outer_signature = try parseCertificateElement(certificate, index);
    try validateAlgorithmIdentifier(certificate, outer_signature);
    if (!std.mem.eql(
        u8,
        certificate[signature_algorithm.start..signature_algorithm.end],
        certificate[outer_signature.start..outer_signature.end],
    )) {
        return error.InvalidCertificate;
    }
    const signature_value = try parseCertificateElement(certificate, outer_signature.end);
    if (signature_value.tag != 0x03 or signature_value.end != outer.end) return error.InvalidCertificate;
    try validateBitStringContent(
        certificate[signature_value.content_start..signature_value.end],
    );
    return .{
        .issuer = issuer,
        .subject = subject,
        .serial = serial,
        .serial_number = certificate[field.content_start..field.end],
    };
}

fn validateAlgorithmIdentifier(
    bytes: []const u8,
    algorithm: DerElement,
) Error!void {
    if (algorithm.tag != 0x30) return error.InvalidCertificate;
    var index = algorithm.content_start;
    const oid = try parseCertificateElement(bytes, index);
    if (oid.tag != 0x06 or oid.content_start == oid.end)
        return error.InvalidCertificate;
    index = oid.end;
    if (index < algorithm.end) {
        index = (try parseCertificateElement(bytes, index)).end;
    }
    if (index != algorithm.end) return error.InvalidCertificate;
}

fn validateName(
    bytes: []const u8,
    name: DerElement,
    allow_empty: bool,
) Error!void {
    if (name.tag != 0x30 or
        (!allow_empty and name.content_start == name.end))
    {
        return error.InvalidCertificate;
    }
    var rdn_index = name.content_start;
    while (rdn_index < name.end) {
        const rdn = try parseCertificateElement(bytes, rdn_index);
        if (rdn.tag != 0x31 or rdn.content_start == rdn.end)
            return error.InvalidCertificate;
        var attribute_index = rdn.content_start;
        while (attribute_index < rdn.end) {
            const attribute = try parseCertificateElement(
                bytes,
                attribute_index,
            );
            if (attribute.tag != 0x30) return error.InvalidCertificate;
            var value_index = attribute.content_start;
            const oid = try parseCertificateElement(bytes, value_index);
            if (oid.tag != 0x06 or oid.content_start == oid.end)
                return error.InvalidCertificate;
            value_index = oid.end;
            const value = try parseCertificateElement(bytes, value_index);
            if (value.end != attribute.end) return error.InvalidCertificate;
            attribute_index = attribute.end;
        }
        if (attribute_index != rdn.end) return error.InvalidCertificate;
        rdn_index = rdn.end;
    }
    if (rdn_index != name.end) return error.InvalidCertificate;
}

fn validateValidity(bytes: []const u8, validity: DerElement) Error!void {
    if (validity.tag != 0x30) return error.InvalidCertificate;
    var index = validity.content_start;
    const not_before = try parseCertificateElement(bytes, index);
    if (!isCertificateTime(not_before)) return error.InvalidCertificate;
    index = not_before.end;
    const not_after = try parseCertificateElement(bytes, index);
    if (!isCertificateTime(not_after) or not_after.end != validity.end)
        return error.InvalidCertificate;
}

fn isCertificateTime(element: DerElement) bool {
    return (element.tag == 0x17 or element.tag == 0x18) and
        element.content_start != element.end;
}

fn validateSubjectPublicKeyInfo(
    bytes: []const u8,
    subject_public_key_info: DerElement,
) Error!void {
    if (subject_public_key_info.tag != 0x30)
        return error.InvalidCertificate;
    var index = subject_public_key_info.content_start;
    const algorithm = try parseCertificateElement(bytes, index);
    try validateAlgorithmIdentifier(bytes, algorithm);
    index = algorithm.end;
    const public_key = try parseCertificateElement(bytes, index);
    if (public_key.tag != 0x03 or
        public_key.end != subject_public_key_info.end)
    {
        return error.InvalidCertificate;
    }
    try validateBitStringContent(
        bytes[public_key.content_start..public_key.end],
    );
}

fn validateBitStringContent(content: []const u8) Error!void {
    if (content.len < 2 or content[0] > 7) return error.InvalidCertificate;
    if (content[0] != 0) {
        const unused_mask = (@as(u8, 1) << @intCast(content[0])) - 1;
        if (content[content.len - 1] & unused_mask != 0)
            return error.InvalidCertificate;
    }
}

fn validateExtensions(bytes: []const u8, explicit: DerElement) Error!void {
    const extensions = try parseCertificateElement(
        bytes,
        explicit.content_start,
    );
    if (extensions.tag != 0x30 or extensions.end != explicit.end)
        return error.InvalidCertificate;
    var index = extensions.content_start;
    while (index < extensions.end) {
        const extension = try parseCertificateElement(bytes, index);
        if (extension.tag != 0x30) return error.InvalidCertificate;
        var field_index = extension.content_start;
        const oid = try parseCertificateElement(bytes, field_index);
        if (oid.tag != 0x06 or oid.content_start == oid.end)
            return error.InvalidCertificate;
        field_index = oid.end;
        var value = try parseCertificateElement(bytes, field_index);
        if (value.tag == 0x01) {
            if (value.end - value.content_start != 1 or
                (bytes[value.content_start] != 0x00 and
                    bytes[value.content_start] != 0xff))
            {
                return error.InvalidCertificate;
            }
            field_index = value.end;
            value = try parseCertificateElement(bytes, field_index);
        }
        if (value.tag != 0x04 or value.end != extension.end)
            return error.InvalidCertificate;
        index = extension.end;
    }
    if (index != extensions.end) return error.InvalidCertificate;
}

fn makeCms(
    allocator: std.mem.Allocator,
    spc: []const u8,
    signed_attributes: []const u8,
    certificate_set: []const u8,
    issuer_and_serial: IssuerAndSerial,
    rsa_signature: []const u8,
) ![]u8 {
    const sha256_algorithm = try algorithmIdentifier(allocator, oid_sha256);
    defer allocator.free(sha256_algorithm);
    const rsa_algorithm = try algorithmIdentifier(allocator, oid_rsa_encryption);
    defer allocator.free(rsa_algorithm);

    var digest_algorithms = std.array_list.Managed(u8).init(allocator);
    defer digest_algorithms.deinit();
    try digest_algorithms.appendSlice(sha256_algorithm);
    const digest_algorithm_set = try wrapDer(allocator, 0x31, digest_algorithms.items);
    defer allocator.free(digest_algorithm_set);

    var encap_body = std.array_list.Managed(u8).init(allocator);
    defer encap_body.deinit();
    try encap_body.appendSlice(oid_spc_indirect_data);
    const explicit_spc = try wrapDer(allocator, 0xa0, spc);
    defer allocator.free(explicit_spc);
    try encap_body.appendSlice(explicit_spc);
    const encap = try wrapDer(allocator, 0x30, encap_body.items);
    defer allocator.free(encap);

    const issuer_and_serial_sequence = blk: {
        var body = std.array_list.Managed(u8).init(allocator);
        defer body.deinit();
        try body.appendSlice(issuer_and_serial.issuer);
        try body.appendSlice(issuer_and_serial.serial);
        break :blk try wrapDer(allocator, 0x30, body.items);
    };
    defer allocator.free(issuer_and_serial_sequence);
    var signer_body = std.array_list.Managed(u8).init(allocator);
    defer signer_body.deinit();
    try signer_body.appendSlice("\x02\x01\x01");
    try signer_body.appendSlice(issuer_and_serial_sequence);
    try signer_body.appendSlice(sha256_algorithm);
    if (signed_attributes.len < 2 or signed_attributes[0] != 0x31) return error.InvalidDer;
    const signed_attributes_element = try parseDerElement(signed_attributes, 0);
    if (signed_attributes_element.end != signed_attributes.len) return error.InvalidDer;
    try signer_body.append(0xa0);
    try appendDerLength(&signer_body, signed_attributes.len - signed_attributes_element.content_start);
    try signer_body.appendSlice(signed_attributes[signed_attributes_element.content_start..]);
    try signer_body.appendSlice(rsa_algorithm);
    try appendDer(&signer_body, 0x04, rsa_signature);
    const signer_info = try wrapDer(allocator, 0x30, signer_body.items);
    defer allocator.free(signer_info);
    const signer_infos = try wrapDer(allocator, 0x31, signer_info);
    defer allocator.free(signer_infos);

    var signed_data_body = std.array_list.Managed(u8).init(allocator);
    defer signed_data_body.deinit();
    try signed_data_body.appendSlice("\x02\x01\x01");
    try signed_data_body.appendSlice(digest_algorithm_set);
    try signed_data_body.appendSlice(encap);
    try signed_data_body.append(0xa0);
    try appendDerLength(&signed_data_body, certificate_set.len);
    try signed_data_body.appendSlice(certificate_set);
    try signed_data_body.appendSlice(signer_infos);
    const signed_data = try wrapDer(allocator, 0x30, signed_data_body.items);
    defer allocator.free(signed_data);

    var content_info = std.array_list.Managed(u8).init(allocator);
    defer content_info.deinit();
    try content_info.appendSlice(oid_signed_data);
    const explicit_signed_data = try wrapDer(allocator, 0xa0, signed_data);
    defer allocator.free(explicit_signed_data);
    try content_info.appendSlice(explicit_signed_data);
    return wrapDer(allocator, 0x30, content_info.items);
}

fn algorithmIdentifier(allocator: std.mem.Allocator, oid: []const u8) ![]u8 {
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try body.appendSlice(oid);
    try body.appendSlice("\x05\x00");
    return wrapDer(allocator, 0x30, body.items);
}

fn wrapDer(allocator: std.mem.Allocator, tag: u8, content: []const u8) ![]u8 {
    var result = std.array_list.Managed(u8).init(allocator);
    errdefer result.deinit();
    try appendDer(&result, tag, content);
    return result.toOwnedSlice();
}

fn appendDer(list: *std.array_list.Managed(u8), tag: u8, content: []const u8) !void {
    try list.append(tag);
    try appendDerLength(list, content.len);
    try list.appendSlice(content);
}

fn appendDerLength(list: *std.array_list.Managed(u8), length: usize) !void {
    if (length < 128) {
        try list.append(@intCast(length));
        return;
    }
    var bytes: [@sizeOf(usize)]u8 = undefined;
    var value = length;
    var count: usize = 0;
    while (value != 0) : (value >>= 8) {
        bytes[bytes.len - 1 - count] = @truncate(value);
        count += 1;
    }
    try list.append(@intCast(0x80 | count));
    try list.appendSlice(bytes[bytes.len - count ..]);
}

const DerElement = struct {
    tag: u8,
    start: usize,
    content_start: usize,
    end: usize,
};

fn parseDerElement(bytes: []const u8, start: usize) Error!DerElement {
    const minimum = std.math.add(usize, start, 2) catch return error.InvalidDer;
    if (minimum > bytes.len) return error.InvalidDer;
    const tag = bytes[start];
    if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
    const length_byte = bytes[start + 1];
    var content_start = minimum;
    var length: usize = 0;
    if (length_byte < 0x80) {
        length = length_byte;
    } else {
        const count: usize = length_byte & 0x7f;
        if (count == 0 or count > @sizeOf(u32)) return error.InvalidDer;
        const length_end = std.math.add(usize, content_start, count) catch return error.InvalidDer;
        if (length_end > bytes.len or bytes[content_start] == 0) return error.InvalidDer;
        var i = content_start;
        while (i < length_end) : (i += 1) {
            length = std.math.mul(usize, length, 256) catch return error.InvalidDer;
            length = std.math.add(usize, length, bytes[i]) catch return error.InvalidDer;
        }
        if (length < 128) return error.InvalidDer;
        content_start = length_end;
    }
    const end = std.math.add(usize, content_start, length) catch return error.InvalidDer;
    if (end > bytes.len) return error.InvalidDer;
    return .{ .tag = tag, .start = start, .content_start = content_start, .end = end };
}

fn validateDerTree(bytes: []const u8, element: DerElement, depth: usize) Error!void {
    if (depth >= max_der_nesting) return error.InvalidDer;
    if ((element.tag & 0x20) == 0) return;
    var index = element.content_start;
    while (index < element.end) {
        const child = try parseDerElement(bytes, index);
        try validateDerTree(bytes, child, depth + 1);
        index = child.end;
    }
    if (index != element.end) return error.InvalidDer;
}

fn parseCertificateElement(bytes: []const u8, start: usize) Error!DerElement {
    const strict = parseDerElement(bytes, start) catch return error.InvalidCertificate;
    const index = std.math.cast(u32, start) orelse return error.InvalidCertificate;
    const standard = std.crypto.Certificate.der.Element.parse(bytes, index) catch return error.InvalidCertificate;
    if (standard.slice.start != strict.content_start or standard.slice.end != strict.end)
        return error.InvalidCertificate;
    return strict;
}

fn validateCertificateDer(bytes: []const u8, element: DerElement) Error!void {
    if ((element.tag & 0x20) == 0) return;
    var index = element.content_start;
    while (index < element.end) {
        const child = try parseCertificateElement(bytes, index);
        try validateCertificateDer(bytes, child);
        index = child.end;
    }
    if (index != element.end) return error.InvalidCertificate;
}

fn align8(length: usize) Error!usize {
    const with_padding = std.math.add(usize, length, 7) catch return error.FileTooLarge;
    return with_padding & ~@as(usize, 7);
}

fn requireU32Size(value: usize) Error!void {
    _ = try asU32(value);
}

fn asU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.FileTooLarge;
}

fn validRsaSignatureLength(length: usize) bool {
    return length == 128 or length == 256 or length == 384 or length == 512;
}

fn readU16Le(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}

fn readU32Le(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn writeU16Le(bytes: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, bytes, value, .little);
}

fn writeU32Le(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

test "prepare aligns and hashes a PE32+ image" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 394);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 400), prepared.aligned_pe.len);
    try std.testing.expectEqual(@as(u8, 0x31), prepared.signed_attributes[0]);
    try std.testing.expectEqualSlices(
        u8,
        "\x30\x68\x30\x33\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0f",
        prepared.spc_indirect_data[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        prepared.spc_indirect_data[55..74],
    );
    try std.testing.expectEqualSlices(
        u8,
        "\x31\x4c\x30\x19\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03\x31\x0c" ++
            "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04\x30\x2f\x06\x09" ++
            "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04\x31\x22\x04\x20",
        prepared.signed_attributes[0..46],
    );
}

test "PE ranges exclude checksum and security directory" {
    const allocator = std.testing.allocator;
    var image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var first = try prepareRsaSha256Alloc(allocator, image);
    defer first.deinit(allocator);
    image[0xd8] ^= 1;
    var second = try prepareRsaSha256Alloc(allocator, image);
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &first.signing_digest, &second.signing_digest);
    const pe = try parseUnsignedPe(image);
    var before: [Sha256.digest_length]u8 = undefined;
    hashPe(image, pe, &before);
    image[0x128] ^= 1;
    var after: [Sha256.digest_length]u8 = undefined;
    hashPe(image, pe, &after);
    try std.testing.expectEqualSlices(u8, &before, &after);
    image[0x128] ^= 1;
    image[0x150] ^= 1;
    var third = try prepareRsaSha256Alloc(allocator, image);
    defer third.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, &first.signing_digest, &third.signing_digest));
}

test "unsigned validation rejects absent directory and signed images" {
    const allocator = std.testing.allocator;
    var image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    try std.testing.expectError(error.InvalidPe, prepareRsaSha256Alloc(allocator, image[0..0x90]));
    writeU32Le(image[0x104..][0..4], 4);
    try std.testing.expectError(error.InvalidPe, prepareRsaSha256Alloc(allocator, image));
    writeU32Le(image[0x104..][0..4], 5);
    writeU32Le(image[0x128..][0..4], 1);
    try std.testing.expectError(error.AlreadySigned, prepareRsaSha256Alloc(allocator, image));
}

test "finish writes an aligned WIN_CERTIFICATE and security directory" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 393);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const certificate = testCertificate();
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256Alloc(allocator, prepared, certificate, &signature);
    defer allocator.free(signed);

    const table_offset = prepared.aligned_pe.len;
    const table_size = @as(usize, readU32Le(signed[0x12c..][0..4]));
    try std.testing.expectEqual(@as(u32, @intCast(table_offset)), readU32Le(signed[0x128..][0..4]));
    try std.testing.expectEqual(@as(usize, 0), table_size % 8);
    try std.testing.expectEqual(@as(u16, 0x0200), readU16Le(signed[table_offset + 4 ..][0..2]));
    try std.testing.expectEqual(@as(u16, 0x0002), readU16Le(signed[table_offset + 6 ..][0..2]));
    const entry_size = @as(usize, readU32Le(signed[table_offset..][0..4]));
    try std.testing.expect(entry_size <= table_size);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            signed[table_offset + 8 ..],
            certificate,
        ) != null,
    );
}

test "finish rejects malformed certificates and unsupported signatures" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const short_signature = [_]u8{0} ** 127;
    try std.testing.expectError(
        error.InvalidSignatureLength,
        finishRsaSha256Alloc(allocator, prepared, testCertificate(), &short_signature),
    );
    try std.testing.expectError(
        error.InvalidSignatureLength,
        finishRsaSha256Alloc(allocator, prepared, testCertificate(), ""),
    );
    const signature = [_]u8{0} ** 128;
    try std.testing.expectError(
        error.InvalidCertificate,
        finishRsaSha256Alloc(allocator, prepared, "\x30\x01\x00", &signature),
    );
}

test "chain-aware finish omits self-issued roots and deduplicates certificates" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const leaf = testCertificate();
    const intermediate = testCertificateTwo();
    const root = testCertificateThree();
    const chain = [_][]const u8{ root, intermediate, leaf, root, intermediate };
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256WithChainAlloc(allocator, prepared, leaf, &chain, &signature);
    defer allocator.free(signed);

    const table_offset = prepared.aligned_pe.len;
    const entry_size = @as(usize, readU32Le(signed[table_offset..][0..4]));
    var parsed = try parseArtifactSigningCertificateChainAlloc(
        allocator,
        signed[table_offset + 8 .. table_offset + entry_size],
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.certificates.len);
    try std.testing.expectEqualSlices(u8, leaf, parsed.certificates[0]);
    try std.testing.expectEqualSlices(u8, intermediate, parsed.certificates[1]);

    const malformed_chain = [_][]const u8{"\x30\x00"};
    try std.testing.expectError(
        error.InvalidCertificate,
        finishRsaSha256WithChainAlloc(allocator, prepared, leaf, &malformed_chain, &signature),
    );
}

test "embedded signer follows SignerInfo instead of certificate order" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const leaf = testCertificate();
    const chain = [_][]const u8{testCertificateTwo()};
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256WithChainAlloc(
        allocator,
        prepared,
        leaf,
        &chain,
        &signature,
    );
    defer allocator.free(signed);

    const signer = try embeddedSigner(signed);
    try std.testing.expectEqual(@as(u16, 0x8664), signer.machine);
    try std.testing.expectEqualSlices(u8, leaf, signer.certificate_der);
    try std.testing.expectEqualSlices(u8, "\x01", signer.serial_number);
    const identity = try extractIssuerAndSerial(leaf);
    try std.testing.expectEqualSlices(u8, identity.subject, signer.subject_der);
    try std.testing.expectEqualSlices(u8, identity.issuer, signer.issuer_der);
}

test "embedded signer rejects unsigned malformed and unresolved signatures" {
    const allocator = std.testing.allocator;
    const unsigned = try makeTestPe(allocator, 512);
    defer allocator.free(unsigned);
    try std.testing.expectError(error.UnsignedPe, embeddedSigner(unsigned));

    var prepared = try prepareRsaSha256Alloc(allocator, unsigned);
    defer prepared.deinit(allocator);
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256Alloc(
        allocator,
        prepared,
        testCertificate(),
        &signature,
    );
    defer allocator.free(signed);

    const table_offset = @as(usize, readU32Le(signed[0x128..][0..4]));
    const malformed = try allocator.dupe(u8, signed);
    defer allocator.free(malformed);
    writeU16Le(malformed[table_offset + 4 ..][0..2], 0x0100);
    try std.testing.expectError(
        error.UnsupportedWinCertificate,
        embeddedSigner(malformed),
    );

    const unresolved = try allocator.dupe(u8, signed);
    defer allocator.free(unresolved);
    const identity = try extractIssuerAndSerial(testCertificate());
    const signer_offset = std.mem.lastIndexOf(
        u8,
        unresolved,
        identity.serial,
    ) orelse
        return error.TestUnexpectedResult;
    unresolved[signer_offset + identity.serial.len - 1] = 0x7f;
    try std.testing.expectError(
        error.SignerCertificateNotFound,
        embeddedSigner(unresolved),
    );
}

test "certificate PEM helpers preserve canonical DER" {
    const certificate = testCertificate();
    const pem = try encodePemCertificateAlloc(
        std.testing.allocator,
        certificate,
    );
    defer std.testing.allocator.free(pem);
    const decoded = try decodePemCertificateAlloc(std.testing.allocator, pem);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, certificate, decoded);
    try std.testing.expectError(
        error.InvalidCertificate,
        validateX509CertificateDer(
            "\x30\x1a" ++
                "\x30\x13\xa0\x03\x02\x01\x02\x02\x02\x00\x01" ++
                "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00" ++
                "\x30\x00\x03\x01\x00",
        ),
    );
}

test "parses Artifact Signing certificate chains and rejects invalid CMS" {
    const allocator = std.testing.allocator;
    const certificates = [_][]const u8{ testCertificate(), testCertificateTwo() };
    const body = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        certificates[0..],
        certificates[0],
    );
    defer allocator.free(body);
    var parsed = try parseArtifactSigningCertificateChainAlloc(allocator, body);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.certificates.len);
    try std.testing.expectEqualSlices(u8, certificates[0], parsed.certificates[0]);
    try std.testing.expectEqualSlices(u8, certificates[1], parsed.certificates[1]);
    try std.testing.expectEqualSlices(
        u8,
        certificates[0],
        try artifactSigningCertificateDer(body),
    );
    const absent_content = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        certificates[0..],
        null,
    );
    defer allocator.free(absent_content);
    try std.testing.expectError(
        error.InvalidDer,
        artifactSigningCertificateDer(absent_content),
    );
    const mismatched_content = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        certificates[0..1],
        certificates[1],
    );
    defer allocator.free(mismatched_content);
    try std.testing.expectError(
        error.InvalidCertificate,
        artifactSigningCertificateDer(mismatched_content),
    );

    try std.testing.expectError(
        error.InvalidDer,
        parseArtifactSigningCertificateChainAlloc(allocator, body[0 .. body.len - 1]),
    );
    const wrong_oid = try makeTestCertificateChainContentInfo(
        allocator,
        "\x06\x03\x2a\x03\x04",
        certificates[0..],
        null,
    );
    defer allocator.free(wrong_oid);
    try std.testing.expectError(
        error.InvalidDer,
        parseArtifactSigningCertificateChainAlloc(allocator, wrong_oid),
    );
    const absent_certificates = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        null,
        null,
    );
    defer allocator.free(absent_certificates);
    try std.testing.expectError(
        error.InvalidDer,
        parseArtifactSigningCertificateChainAlloc(allocator, absent_certificates),
    );
    const duplicate_certificates = [_][]const u8{ testCertificate(), testCertificate() };
    const duplicate_body = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        duplicate_certificates[0..],
        null,
    );
    defer allocator.free(duplicate_body);
    try std.testing.expectError(
        error.InvalidCertificate,
        parseArtifactSigningCertificateChainAlloc(allocator, duplicate_body),
    );
    const non_certificate = [_][]const u8{"\x04\x01\x00"};
    const non_certificate_body = try makeTestCertificateChainContentInfo(
        allocator,
        oid_signed_data,
        non_certificate[0..],
        null,
    );
    defer allocator.free(non_certificate_body);
    try std.testing.expectError(
        error.InvalidCertificate,
        parseArtifactSigningCertificateChainAlloc(allocator, non_certificate_body),
    );
}

test "alignment padding contributes to PE digest" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 393);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const pe = try parseUnsignedPe(prepared.aligned_pe);
    var original: [Sha256.digest_length]u8 = undefined;
    hashPe(prepared.aligned_pe, pe, &original);
    prepared.aligned_pe[prepared.aligned_pe.len - 1] = 1;
    var changed: [Sha256.digest_length]u8 = undefined;
    hashPe(prepared.aligned_pe, pe, &changed);
    try std.testing.expect(!std.mem.eql(u8, &original, &changed));
}

test "a signature commits to the image it was made from" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 393);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256Alloc(
        allocator,
        prepared,
        testCertificate(),
        &signature,
    );
    defer allocator.free(signed);

    // The image digest survives signing: attaching a certificate table does
    // not change what the signature is over, which is the whole reason a
    // signed image can be checked against the unsigned bytes it came from.
    const unsigned_digest = try imageSha256(prepared.aligned_pe);
    const signed_digest = try imageSha256(signed);
    try std.testing.expectEqualSlices(u8, &unsigned_digest, &signed_digest);
    const claimed = try embeddedImageSha256(signed);
    try std.testing.expectEqualSlices(u8, &unsigned_digest, &claimed);
}

test "a signature over other bytes is not mistaken for one over these" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256Alloc(
        allocator,
        prepared,
        testCertificate(),
        &signature,
    );
    defer allocator.free(signed);

    // A byte of payload changed after signing. The signature is still
    // structurally intact and still names the same signer; only the digest
    // comparison notices, which is why the comparison exists.
    const table_offset = prepared.aligned_pe.len;
    signed[table_offset - 1] = 1;
    const recomputed = try imageSha256(signed);
    const claimed = try embeddedImageSha256(signed);
    try std.testing.expect(!std.mem.eql(u8, &recomputed, &claimed));
    _ = try embeddedSigner(signed);
}

test "image digest rejects an unsigned image with trailing bytes it cannot place" {
    const allocator = std.testing.allocator;
    const image = try makeTestPe(allocator, 512);
    defer allocator.free(image);
    var prepared = try prepareRsaSha256Alloc(allocator, image);
    defer prepared.deinit(allocator);
    const signature = [_]u8{0} ** 256;
    const signed = try finishRsaSha256Alloc(
        allocator,
        prepared,
        testCertificate(),
        &signature,
    );
    defer allocator.free(signed);

    const extended = try allocator.alloc(u8, signed.len + 8);
    defer allocator.free(extended);
    @memcpy(extended[0..signed.len], signed);
    @memset(extended[signed.len..], 0);
    try std.testing.expectError(
        error.TrailingDataAfterCertificateTable,
        imageSha256(extended),
    );
    try std.testing.expectError(error.UnsignedPe, embeddedImageSha256(image));
}

fn testCertificate() []const u8 {
    return testCertificateSerial(1);
}
fn testCertificateTwo() []const u8 {
    return "\x30\x81\x93\x30\x7e\xa0\x03\x02\x01\x02\x02\x01\x02" ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" ++
        "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
        "Test Signer" ++
        "\x30\x1e\x17\x0d\x32\x36\x30\x31\x30\x31\x30\x30\x30\x30" ++
        "\x30\x30\x5a\x17\x0d\x32\x37\x30\x31\x30\x31\x30\x30\x30" ++
        "\x30\x30\x30\x5a" ++
        "\x30\x17\x31\x15\x30\x13\x06\x03\x55\x04\x03\x0c\x0c" ++
        "Intermediate" ++
        "\x30\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" ++
        "\x01\x05\x00\x03\x03\x00\x30\x00" ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05" ++
        "\x00\x03\x02\x00\x00";
}

fn testCertificateThree() []const u8 {
    return testCertificateSerial(3);
}

fn testCertificateSerial(comptime serial: u8) []const u8 {
    return "\x30\x81\x92\x30\x7d\xa0\x03\x02\x01\x02\x02\x01" ++
        [_]u8{serial} ++
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

fn makeTestCertificateChainContentInfo(
    allocator: std.mem.Allocator,
    content_type: []const u8,
    certificates: ?[]const []const u8,
    encapsulated_content: ?[]const u8,
) ![]u8 {
    var encap_content = std.array_list.Managed(u8).init(allocator);
    defer encap_content.deinit();
    try encap_content.appendSlice(oid_data);
    if (encapsulated_content) |content| {
        const octet_string = try wrapDer(allocator, 0x04, content);
        defer allocator.free(octet_string);
        const explicit_content = try wrapDer(allocator, 0xa0, octet_string);
        defer allocator.free(explicit_content);
        try encap_content.appendSlice(explicit_content);
    }
    const encap = try wrapDer(allocator, 0x30, encap_content.items);
    defer allocator.free(encap);

    var signed_data_content = std.array_list.Managed(u8).init(allocator);
    defer signed_data_content.deinit();
    try signed_data_content.appendSlice("\x02\x01\x01\x31\x00");
    try signed_data_content.appendSlice(encap);
    if (certificates) |chain| {
        var certificate_set = std.array_list.Managed(u8).init(allocator);
        defer certificate_set.deinit();
        for (chain) |certificate| try certificate_set.appendSlice(certificate);
        try appendDer(&signed_data_content, 0xa0, certificate_set.items);
    }
    try signed_data_content.appendSlice("\x31\x00");
    const signed_data = try wrapDer(allocator, 0x30, signed_data_content.items);
    defer allocator.free(signed_data);

    var content_info = std.array_list.Managed(u8).init(allocator);
    defer content_info.deinit();
    try content_info.appendSlice(content_type);
    try appendDer(&content_info, 0xa0, signed_data);
    return wrapDer(allocator, 0x30, content_info.items);
}

fn makeTestPe(allocator: std.mem.Allocator, length: usize) ![]u8 {
    var image = try allocator.alloc(u8, length);
    @memset(image, 0);
    image[0] = 'M';
    image[1] = 'Z';
    writeU32Le(image[0x3c..][0..4], 0x80);
    @memcpy(image[0x80..0x84], "PE\x00\x00");
    writeU16Le(image[0x84..][0..2], 0x8664);
    writeU16Le(image[0x94..][0..2], 0xf0);
    writeU16Le(image[0x98..][0..2], 0x20b);
    writeU32Le(image[0x104..][0..4], 5);
    return image;
}
