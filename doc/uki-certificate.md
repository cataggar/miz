# UKI signing certificates

`vmiz uki certificate` extracts the X.509 certificate identified by the
Authenticode CMS `SignerInfo` in a disk image's UKIs. It reads the image,
GPT, FAT32 ESP, PE certificate table, CMS, and X.509 data natively; it does
not mount the image or invoke OpenSSL, `sbverify`, or guest code.

## Export PEM

```console
vmiz uki certificate AzureLinux-4.0-x86_64.qcow2 \
  --output release.pem
```

The output is one canonical PEM `CERTIFICATE` block. Decoding it reproduces
the exact DER certificate embedded in the UKIs. The file is published
atomically only after the complete image passes inspection.

To require a previously trusted canonical-DER SHA-256 fingerprint:

```console
vmiz uki certificate AzureLinux-4.0-x86_64.qcow2 \
  --output release.pem \
  --expected-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`sha256:<hex>` is accepted as well. A mismatch fails without publishing the
output.

## JSON

Use `--output=json` for machine-readable output on stdout:

```console
vmiz uki certificate AzureLinux-4.0-aarch64.qcow2 --output=json
```

The version 1 document contains:

```json
{
  "schema": 1,
  "certificate_sha256": "<canonical-DER-SHA-256>",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n",
  "signer": {
    "subject_der_base64": "...",
    "issuer_der_base64": "...",
    "serial_number_hex": "..."
  },
  "uki_paths": [
    "EFI/BOOT/BOOTAA64.EFI",
    "EFI/Linux/example.efi"
  ]
}
```

The subject and issuer are complete DER-encoded X.509 names rather than
lossy display strings. `serial_number_hex` preserves the DER INTEGER content,
including a leading zero octet when present.

## Image requirements

The command supports raw, fixed or dynamic VHD, VHDX, and standalone QCOW2
through `vmiz.Image`. QCOW2 backing files and external data files are rejected
so the inspected result cannot depend on separately mutable host files.

The image must have:

- a valid mirrored GPT with exactly one EFI System Partition;
- a readable FAT32 ESP;
- exactly one architecture fallback, either `EFI/BOOT/BOOTX64.EFI` or
  `EFI/BOOT/BOOTAA64.EFI`;
- at least one regular `EFI/Linux/*.efi` UKI;
- a structurally valid Authenticode signature on every selected UKI;
- one PE architecture and one byte-identical signer certificate across the
  fallback and all named UKIs.

The certificate is selected by matching the CMS `SignerInfo` issuer and
serial number. Certificate ordering in the CMS chain is not trusted.
Unsigned, malformed, mixed-architecture, mixed-signer, ambiguous, or
fingerprint-mismatched images fail closed.

## Trust boundary

**A certificate extracted from an untrusted image is not trusted.** An image
can embed an arbitrary certificate and claim it as its signer. Before using
the output for Secure Boot enrollment, independently pin the image digest,
pass a trusted `--expected-sha256`, or do both.

This command identifies the certificate claimed by Authenticode. It does not
cryptographically verify the PE content digest or RSA signature and does not
evaluate certificate-chain trust, validity time, revocation, or timestamps.
Secure Boot enrollment and QEMU launch policy are tracked separately in
issue #241.
