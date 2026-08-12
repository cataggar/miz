#!/usr/bin/env python3
"""Validate and bind Azure Linux release artifacts across workflow jobs."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

try:
    from scripts.azure_vhd import (
        AZURE_VHD_ALIGNMENT,
        VHD_FOOTER_BYTES,
        VHD_MAX_CHS_SECTORS,
        inspect_azure_vhd,
        validate_azure_vhd_info,
    )
except ModuleNotFoundError:
    from azure_vhd import (
        AZURE_VHD_ALIGNMENT,
        VHD_FOOTER_BYTES,
        VHD_MAX_CHS_SECTORS,
        inspect_azure_vhd,
        validate_azure_vhd_info,
    )


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ARTIFACT_SIGNING_ENDPOINT_RE = re.compile(
    r"^https://[a-z0-9.-]+\.codesigning\.azure\.net$"
)
ARTIFACT_SIGNING_RESOURCE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
EXPECTED = {
    "x86_64-full": ("x86_64", "full", "AzureLinux-4.0-x86_64.qcow2"),
    "aarch64-full": ("aarch64", "full", "AzureLinux-4.0-aarch64.qcow2"),
    "x86_64-core": ("x86_64", "core", "AzureLinux-4.0-x86_64.core.qcow2"),
    "aarch64-core": ("aarch64", "core", "AzureLinux-4.0-aarch64.core.qcow2"),
}
RELEASE_ORDER = tuple(EXPECTED)
AZURE_CONTRACTS = {
    "matching-architecture-gen2",
    "trusted-launch",
    "secure-boot",
    "vtpm",
    "uefi-db-signer",
    "signed-uki",
    "kernel-lockdown",
    "module-signatures",
    "key-only-ssh",
    "agent-ready",
    "root-growth",
    "resource-disk",
    "managed-data-disk",
    "reboot-reconnect",
    "runtime-flavor-identity",
}
PRIVATE_KEY_PEM_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not a lowercase SHA-256")
    return value


def require_commit(value: object, label: str = "source_commit") -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        fail(f"{label} is not a full lowercase commit SHA")
    return value


def has_exact_contracts(value: object, expected: set[str]) -> bool:
    return (
        isinstance(value, list)
        and len(value) == len(expected)
        and all(isinstance(item, str) for item in value)
        and set(value) == expected
    )


def validate_azure_uefi_settings(
    settings: object,
    certificate_sha256: str,
) -> dict[str, object]:
    if not isinstance(settings, dict) or set(settings) != {
        "signatureTemplateNames",
        "additionalSignatures",
    }:
        fail("Azure custom UEFI settings have an unexpected shape")
    if settings.get("signatureTemplateNames") != [
        "MicrosoftUefiCertificateAuthorityTemplate"
    ]:
        fail("Azure custom UEFI settings do not retain the Microsoft template")
    additional = settings.get("additionalSignatures")
    if not isinstance(additional, dict) or set(additional) != {"db"}:
        fail("Azure custom UEFI additional signatures are invalid")
    db = additional.get("db")
    if (
        not isinstance(db, list)
        or len(db) != 1
        or not isinstance(db[0], dict)
        or db[0].get("type") != "x509"
        or set(db[0]) != {"type", "value"}
        or not isinstance(db[0].get("value"), list)
        or len(db[0]["value"]) != 1
        or not isinstance(db[0]["value"][0], str)
    ):
        fail("Azure custom UEFI db signature is invalid")
    try:
        certificate = base64.b64decode(db[0]["value"][0], validate=True)
    except (ValueError, binascii.Error):
        fail("Azure custom UEFI certificate is not canonical base64")
    if hashlib.sha256(certificate).hexdigest() != certificate_sha256:
        fail("Azure custom UEFI certificate fingerprint mismatch")
    return settings


def gallery_uefi_settings(document: dict[str, object]) -> object:
    properties = document.get("properties")
    if not isinstance(properties, dict):
        return None
    security_profile = properties.get("securityProfile")
    if not isinstance(security_profile, dict):
        return None
    return security_profile.get("uefiSettings")


def validate_azure_gallery_uefi_settings(
    request: dict[str, object],
    response: dict[str, object],
    certificate_sha256: str,
) -> dict[str, object]:
    request_uefi = gallery_uefi_settings(request)
    response_uefi = gallery_uefi_settings(response)
    if not isinstance(request_uefi, dict):
        fail("Azure gallery request omitted custom UEFI settings")
    if response_uefi is not None and request_uefi != response_uefi:
        fail("Azure gallery version returned different custom UEFI settings")
    validate_azure_uefi_settings(request_uefi, certificate_sha256)
    return request_uefi


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def contains_private_key(data: bytes) -> bool:
    if any(marker in data for marker in PRIVATE_KEY_PEM_MARKERS):
        return True

    def read_tlv(
        offset: int, limit: int
    ) -> tuple[int, int, int] | None:
        if offset + 2 > limit:
            return None
        tag = data[offset]
        length = data[offset + 1]
        cursor = offset + 2
        if length & 0x80:
            length_bytes = length & 0x7F
            if (
                length_bytes == 0
                or length_bytes > 4
                or cursor + length_bytes > limit
            ):
                return None
            length = int.from_bytes(data[cursor : cursor + length_bytes], "big")
            cursor += length_bytes
        end = cursor + length
        if end > limit:
            return None
        return tag, cursor, end

    def der_private_key_at(offset: int) -> bool:
        root = read_tlv(offset, len(data))
        if root is None or root[0] != 0x30:
            return False
        first = read_tlv(root[1], root[2])
        if first is None:
            return False
        if first[0] == 0x02:
            version = data[first[1] : first[2]]
            return version in (b"\x00", b"\x01", b"\x03")

        second = read_tlv(first[2], root[2])
        if (
            first[0] != 0x30
            or second is None
            or second[0] != 0x04
            or second[2] != root[2]
        ):
            return False
        algorithm_oid = read_tlv(first[1], first[2])
        return algorithm_oid is not None and algorithm_oid[0] == 0x06

    cursor = 0
    while (candidate := data.find(b"\x30", cursor)) >= 0:
        if der_private_key_at(candidate):
            return True
        cursor = candidate + 1
    return False


def validate_identity(
    document: dict[str, object],
    *,
    expected_type: str,
    key: str | None = None,
    source_commit: str | None = None,
) -> tuple[str, str, str, str]:
    if document.get("schema") != 1 or document.get("type") != expected_type:
        fail(f"invalid {expected_type} schema")
    actual_key = document.get("key")
    if not isinstance(actual_key, str) or actual_key not in EXPECTED:
        fail(f"invalid candidate key: {actual_key!r}")
    if key is not None and actual_key != key:
        fail(f"candidate key mismatch: expected {key}, got {actual_key}")
    architecture, flavor, asset_name = EXPECTED[actual_key]
    if document.get("architecture") != architecture:
        fail(f"{actual_key}: architecture mismatch")
    if document.get("flavor") != flavor:
        fail(f"{actual_key}: flavor mismatch")
    if document.get("asset_name") != asset_name:
        fail(f"{actual_key}: asset name mismatch")
    actual_commit = require_commit(document.get("source_commit"))
    if source_commit is not None and actual_commit != source_commit:
        fail(f"{actual_key}: source commit mismatch")
    return actual_key, architecture, flavor, asset_name


def provenance_records(root: Path) -> list[dict[str, object]]:
    if not root.is_dir():
        fail(f"provenance directory is missing: {root}")
    records: list[dict[str, object]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if contains_private_key(path.read_bytes()):
            fail(f"private key material is forbidden in provenance: {path}")
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )
    if not records:
        fail(f"provenance directory is empty: {root}")
    return records


def validate_signing_provenance(
    root: Path,
    architecture: str,
    flavor: str,
) -> dict[str, object]:
    path = root / f"uki-signing-{flavor}-{architecture}.json"
    document = read_json(path)
    if document.get("schema") != 1 or document.get("type") != "zvmi-uki-signing":
        fail("invalid UKI signing provenance schema")
    if document.get("architecture") != architecture or document.get("flavor") != flavor:
        fail("UKI signing provenance architecture/flavor mismatch")
    if document.get("signer_mode") != "external-command":
        fail("release UKIs were not signed by the external provider")
    certificate_sha256 = require_sha256(
        document.get("certificate_sha256"), "UKI signing certificate fingerprint"
    )
    certificate_der_base64 = document.get("certificate_der_base64")
    if not isinstance(certificate_der_base64, str):
        fail("canonical DER UKI signing certificate is absent")
    try:
        certificate_der = base64.b64decode(certificate_der_base64, validate=True)
    except (ValueError, binascii.Error):
        fail("canonical DER UKI signing certificate is not valid base64")
    if (
        not certificate_der
        or hashlib.sha256(certificate_der).hexdigest() != certificate_sha256
    ):
        fail("canonical DER UKI signing certificate fingerprint mismatch")
    if document.get("signature_verification") != "success":
        fail("UKI signature verification did not explicitly succeed")
    if not isinstance(document.get("certificate_details"), str) or not document[
        "certificate_details"
    ]:
        fail("UKI signing certificate details are absent")

    provider = document.get("provider")
    if not isinstance(provider, dict) or set(provider) != {
        "name",
        "endpoint",
        "account",
        "profile",
        "signing_certificate_sha256",
    }:
        fail("Artifact Signing provider identity is absent")
    if provider.get("name") != "azure-artifact-signing":
        fail("unexpected UKI signing provider")
    endpoint = provider.get("endpoint")
    account = provider.get("account")
    profile = provider.get("profile")
    if (
        not isinstance(endpoint, str)
        or ARTIFACT_SIGNING_ENDPOINT_RE.fullmatch(endpoint) is None
        or not isinstance(account, str)
        or ARTIFACT_SIGNING_RESOURCE_RE.fullmatch(account) is None
        or not isinstance(profile, str)
        or ARTIFACT_SIGNING_RESOURCE_RE.fullmatch(profile) is None
    ):
        fail("invalid Artifact Signing provider identity")
    signing_certificate_sha256 = require_sha256(
        provider.get("signing_certificate_sha256"),
        "Artifact Signing leaf certificate fingerprint",
    )

    files = document.get("files")
    if not isinstance(files, list) or len(files) < 2:
        fail("UKI signing provenance file bindings are absent")
    fallback_path = (
        "EFI/BOOT/BOOTX64.EFI"
        if architecture == "x86_64"
        else "EFI/BOOT/BOOTAA64.EFI"
    )
    seen: set[str] = set()
    named_digests: set[str] = set()
    named_operations: dict[str, set[str]] = {}
    fallback_digest: str | None = None
    fallback_operation: str | None = None
    for record in files:
        if not isinstance(record, dict):
            fail("invalid UKI signing file record")
        uki_path = record.get("path")
        if not isinstance(uki_path, str) or uki_path in seen:
            fail("invalid or duplicate UKI signing path")
        if uki_path != fallback_path and not (
            uki_path.startswith("EFI/Linux/") and uki_path.lower().endswith(".efi")
        ):
            fail(f"unexpected UKI signing path: {uki_path}")
        seen.add(uki_path)
        unsigned = require_sha256(
            record.get("unsigned_sha256"), f"{uki_path} unsigned UKI digest"
        )
        signed = require_sha256(record.get("signed_sha256"), f"{uki_path} signed UKI digest")
        finalized = require_sha256(
            record.get("finalized_sha256"), f"{uki_path} finalized UKI digest"
        )
        if unsigned == signed or signed != finalized:
            fail(f"{uki_path}: invalid signed/finalized UKI digest binding")
        if type(record.get("signed_bytes")) is not int or record["signed_bytes"] <= 0:
            fail(f"{uki_path}: invalid signed UKI size")
        operation_id = record.get("signing_operation_id")
        if not isinstance(operation_id, str) or UUID_RE.fullmatch(operation_id) is None:
            fail(f"{uki_path}: invalid Artifact Signing operation ID")
        if record.get("signing_certificate_sha256") != signing_certificate_sha256:
            fail(f"{uki_path}: Artifact Signing leaf fingerprint mismatch")
        if uki_path == fallback_path:
            fallback_digest = signed
            fallback_operation = operation_id
        else:
            named_digests.add(signed)
            named_operations.setdefault(signed, set()).add(operation_id)
    if fallback_digest is None or fallback_digest not in named_digests:
        fail("fallback UKI is not byte-identical to a named signed UKI")
    if fallback_operation not in named_operations[fallback_digest]:
        fail("fallback UKI does not retain its named UKI signing operation")
    return {
        "certificate_sha256": certificate_sha256,
        "certificate_der_base64": certificate_der_base64,
        "fallback_uki_sha256": fallback_digest,
        "provider": {
            "name": provider["name"],
            "endpoint": endpoint,
            "account": account,
            "profile": profile,
        },
        "signing_certificate_sha256": signing_certificate_sha256,
        "signer_mode": document["signer_mode"],
        "provenance_path": path.relative_to(root).as_posix(),
    }


def provenance_digest(records: list[dict[str, object]]) -> str:
    encoded = json.dumps(records, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def candidate_command(args: argparse.Namespace) -> None:
    asset = args.asset.resolve()
    if not asset.is_file():
        fail(f"candidate asset is missing: {asset}")
    if args.key not in EXPECTED:
        fail(f"unknown candidate key: {args.key}")
    architecture, flavor, asset_name = EXPECTED[args.key]
    if args.architecture != architecture or args.flavor != flavor:
        fail(f"{args.key}: architecture/flavor arguments do not match")
    if asset.name != asset_name:
        fail(f"{args.key}: expected asset {asset_name}, got {asset.name}")
    source_commit = require_commit(args.source_commit)
    provenance_root = args.provenance_dir.resolve()
    records = provenance_records(provenance_root)
    signing = validate_signing_provenance(provenance_root, architecture, flavor)
    digest = sha256(asset)
    if args.validated_sha256 != digest:
        fail(f"{args.key}: build validation digest does not match candidate bytes")
    if args.virtual_size <= 0:
        fail("virtual size must be positive")
    write_json(
        args.output,
        {
            "schema": 1,
            "type": "azurelinux4-candidate",
            "key": args.key,
            "architecture": architecture,
            "flavor": flavor,
            "asset_name": asset_name,
            "source_commit": source_commit,
            "sha256": digest,
            "bytes": asset.stat().st_size,
            "virtual_size": args.virtual_size,
            "build_validation": {
                "status": "success",
                "validated_sha256": args.validated_sha256,
                "runner": args.runner,
            },
            "provenance": {
                "digest": provenance_digest(records),
                "files": records,
            },
            "uki_signing": signing,
            "workflow": {
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
            },
        },
    )


def verify_candidate(
    manifest_path: Path,
    asset_path: Path,
    *,
    key: str | None = None,
    source_commit: str | None = None,
) -> dict[str, object]:
    document = read_json(manifest_path)
    actual_key, _, _, asset_name = validate_identity(
        document,
        expected_type="azurelinux4-candidate",
        key=key,
        source_commit=source_commit,
    )
    if asset_path.name != asset_name or not asset_path.is_file():
        fail(f"{actual_key}: exact candidate asset is missing")
    digest = require_sha256(document.get("sha256"), f"{actual_key} candidate digest")
    if sha256(asset_path) != digest:
        fail(f"{actual_key}: candidate bytes do not match the bound digest")
    if document.get("bytes") != asset_path.stat().st_size:
        fail(f"{actual_key}: candidate size mismatch")
    virtual_size = document.get("virtual_size")
    if not isinstance(virtual_size, int) or virtual_size <= 0:
        fail(f"{actual_key}: invalid virtual size")
    build_validation = document.get("build_validation")
    if (
        not isinstance(build_validation, dict)
        or build_validation.get("status") != "success"
    ):
        fail(f"{actual_key}: build validation is not explicitly successful")
    if build_validation.get("validated_sha256") != digest:
        fail(f"{actual_key}: build validation did not validate published bytes")
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        fail(f"{actual_key}: provenance is absent")
    require_sha256(provenance.get("digest"), f"{actual_key} provenance digest")
    files = provenance.get("files")
    if not isinstance(files, list) or not files:
        fail(f"{actual_key}: provenance file bindings are absent")
    provenance_root = manifest_path.parent / "internal-provenance"
    actual_paths = {
        path.relative_to(provenance_root).as_posix()
        for path in provenance_root.rglob("*")
        if path.is_file()
    }
    bound_paths: set[str] = set()
    for record in files:
        if not isinstance(record, dict):
            fail(f"{actual_key}: invalid provenance record")
        relative = record.get("path")
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in bound_paths
        ):
            fail(f"{actual_key}: invalid provenance path")
        path = provenance_root / relative
        if path.is_file() and contains_private_key(path.read_bytes()):
            fail(f"{actual_key}: private key material is forbidden in provenance")
        if not path.is_file() or record.get("bytes") != path.stat().st_size:
            fail(f"{actual_key}: provenance file/size mismatch for {relative}")
        if record.get("sha256") != sha256(path):
            fail(f"{actual_key}: provenance digest mismatch for {relative}")
        bound_paths.add(relative)
    if bound_paths != actual_paths:
        fail(f"{actual_key}: provenance file allowlist mismatch")
    if provenance.get("digest") != provenance_digest(files):
        fail(f"{actual_key}: aggregate provenance digest mismatch")
    signing = document.get("uki_signing")
    if not isinstance(signing, dict):
        fail(f"{actual_key}: UKI signing binding is absent")
    actual_signing = validate_signing_provenance(provenance_root, document["architecture"], document["flavor"])
    if signing != actual_signing:
        fail(f"{actual_key}: UKI signing binding does not match provenance")
    return document


def verify_candidate_command(args: argparse.Namespace) -> None:
    document = verify_candidate(
        args.manifest,
        args.asset,
        key=args.key,
        source_commit=args.source_commit,
    )
    print(document["sha256"])
    print(document["bytes"])
    print(document["virtual_size"])


def verify_vhd_command(args: argparse.Namespace) -> None:
    geometry = inspect_azure_vhd(args.info, args.vhd)
    print(geometry.current_size)
    print(geometry.file_size)


def azure_result_command(args: argparse.Namespace) -> None:
    candidate = verify_candidate(
        args.manifest,
        args.asset,
        key=args.key,
        source_commit=args.source_commit,
    )
    vhd = args.vhd.resolve()
    if not vhd.is_file():
        fail(f"derived VHD is missing: {vhd}")
    if (
        type(args.vhd_current_size) is not int
        or args.vhd_current_size <= 0
        or args.vhd_current_size % AZURE_VHD_ALIGNMENT != 0
        or vhd.stat().st_size != args.vhd_current_size + VHD_FOOTER_BYTES
    ):
        fail("derived VHD current-size evidence is inconsistent")
    request = read_json(args.uefi_request)
    response = read_json(args.uefi_response)
    request_uefi = validate_azure_gallery_uefi_settings(
        request,
        response,
        candidate["uki_signing"]["certificate_sha256"],
    )
    write_json(
        args.output,
        {
            "schema": 1,
            "type": "azurelinux4-azure-acceptance",
            "key": candidate["key"],
            "architecture": candidate["architecture"],
            "flavor": candidate["flavor"],
            "asset_name": candidate["asset_name"],
            "source_commit": candidate["source_commit"],
            "qcow_sha256": candidate["sha256"],
            "azure_accepted_sha256": sha256(args.asset),
            "derived_vhd_sha256": sha256(vhd),
            "derived_vhd_bytes": vhd.stat().st_size,
            "derived_vhd_current_size": args.vhd_current_size,
            "certificate_sha256": candidate["uki_signing"]["certificate_sha256"],
            "signing_certificate_sha256": candidate["uki_signing"][
                "signing_certificate_sha256"
            ],
            "fallback_uki_sha256": candidate["uki_signing"]["fallback_uki_sha256"],
            "image_version_id": args.image_version_id,
            "uefi_settings": request_uefi,
            "status": "success",
            "location": args.location,
            "vm_size": args.vm_size,
            "resource_group": args.resource_group,
            "contracts": sorted(AZURE_CONTRACTS),
            "workflow": {
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
            },
        },
    )


def find_documents(root: Path, filename: str) -> dict[str, tuple[Path, dict[str, object]]]:
    result: dict[str, tuple[Path, dict[str, object]]] = {}
    paths = sorted(root.rglob(filename))
    if len(paths) != len(EXPECTED):
        fail(f"expected exactly four {filename} files under {root}, found {len(paths)}")
    for path in paths:
        document = read_json(path)
        key = document.get("key")
        if not isinstance(key, str) or key in result:
            fail(f"duplicate or invalid key in {path}")
        result[key] = (path, document)
    if set(result) != set(EXPECTED):
        fail(f"{filename} candidate set is not exact")
    return result


def stage_command(args: argparse.Namespace) -> None:
    source_commit = require_commit(args.source_commit)
    candidates_root = args.candidates.resolve()
    azure_root = args.azure_results.resolve()
    forbidden = list(candidates_root.rglob("*.sha256")) + list(azure_root.rglob("*.sha256"))
    if forbidden:
        fail("SHA-256 sidecar files are forbidden")

    candidates = find_documents(candidates_root, "candidate.json")
    azure_results = find_documents(azure_root, "azure-result.json")
    qcow_paths = sorted(candidates_root.rglob("*.qcow2"))
    if len(qcow_paths) != len(EXPECTED):
        fail(f"expected exactly four candidate QCOW2 files, found {len(qcow_paths)}")

    output = args.output.resolve()
    if output.exists():
        if any(output.iterdir()):
            fail(f"staging directory is not empty: {output}")
    else:
        output.mkdir(parents=True)

    staged: list[dict[str, object]] = []
    release_certificate_sha256: str | None = None
    release_signing_certificate_sha256: str | None = None
    release_signing_provider: dict[str, object] | None = None
    for key in RELEASE_ORDER:
        manifest_path, candidate = candidates[key]
        _, architecture, flavor, asset_name = validate_identity(
            candidate,
            expected_type="azurelinux4-candidate",
            key=key,
            source_commit=source_commit,
        )
        asset_path = manifest_path.parent / asset_name
        candidate = verify_candidate(
            manifest_path,
            asset_path,
            key=key,
            source_commit=source_commit,
        )

        _, azure = azure_results[key]
        validate_identity(
            azure,
            expected_type="azurelinux4-azure-acceptance",
            key=key,
            source_commit=source_commit,
        )
        digest = require_sha256(candidate.get("sha256"), f"{key} candidate digest")
        if azure.get("status") != "success":
            fail(f"{key}: Azure acceptance is not explicitly successful")
        if azure.get("qcow_sha256") != digest or azure.get("azure_accepted_sha256") != digest:
            fail(f"{key}: Azure acceptance did not validate published bytes")
        signing = candidate.get("uki_signing")
        if not isinstance(signing, dict):
            fail(f"{key}: UKI signing binding is absent")
        certificate_sha256 = require_sha256(
            signing.get("certificate_sha256"), f"{key} signing certificate fingerprint"
        )
        fallback_uki_sha256 = require_sha256(
            signing.get("fallback_uki_sha256"), f"{key} fallback UKI digest"
        )
        signing_certificate_sha256 = require_sha256(
            signing.get("signing_certificate_sha256"),
            f"{key} Artifact Signing leaf certificate fingerprint",
        )
        signing_provider = signing.get("provider")
        if not isinstance(signing_provider, dict):
            fail(f"{key}: Artifact Signing provider identity is absent")
        if (
            azure.get("certificate_sha256") != certificate_sha256
            or azure.get("signing_certificate_sha256")
            != signing_certificate_sha256
            or azure.get("fallback_uki_sha256") != fallback_uki_sha256
        ):
            fail(f"{key}: Azure acceptance did not bind the signed UKI identity")
        validate_azure_uefi_settings(azure.get("uefi_settings"), certificate_sha256)
        if (
            not isinstance(azure.get("image_version_id"), str)
            or not azure["image_version_id"].startswith("/subscriptions/")
        ):
            fail(f"{key}: Azure gallery image-version identity is absent")
        if release_certificate_sha256 is None:
            release_certificate_sha256 = certificate_sha256
        elif release_certificate_sha256 != certificate_sha256:
            fail("release candidates do not share one UKI signing certificate")
        if release_signing_certificate_sha256 is None:
            release_signing_certificate_sha256 = signing_certificate_sha256
            release_signing_provider = signing_provider
        elif (
            release_signing_certificate_sha256 != signing_certificate_sha256
            or release_signing_provider != signing_provider
        ):
            fail("release candidates do not share one Artifact Signing identity")
        require_sha256(azure.get("derived_vhd_sha256"), f"{key} VHD digest")
        contracts = azure.get("contracts")
        if not has_exact_contracts(contracts, AZURE_CONTRACTS):
            fail(f"{key}: Azure contract results are absent")
        derived_vhd_bytes = azure.get("derived_vhd_bytes")
        derived_vhd_current_size = azure.get("derived_vhd_current_size")
        if (
            not isinstance(derived_vhd_bytes, int)
            or not isinstance(derived_vhd_current_size, int)
            or derived_vhd_current_size <= 0
            or derived_vhd_current_size % AZURE_VHD_ALIGNMENT != 0
            or derived_vhd_bytes != derived_vhd_current_size + VHD_FOOTER_BYTES
        ):
            fail(f"{key}: derived VHD size binding is absent")
        if not isinstance(azure.get("location"), str) or not azure["location"]:
            fail(f"{key}: Azure location is absent")
        if not isinstance(azure.get("vm_size"), str) or not azure["vm_size"]:
            fail(f"{key}: Azure VM size is absent")

        destination = output / asset_name
        try:
            os.link(asset_path, destination)
        except OSError:
            shutil.copyfile(asset_path, destination)
        if sha256(destination) != digest:
            fail(f"{key}: staging changed candidate bytes")
        build_validation = candidate["build_validation"]
        provenance = candidate["provenance"]
        if not isinstance(build_validation, dict) or not isinstance(provenance, dict):
            fail(f"{key}: validated metadata changed type")
        staged.append(
            {
                "key": key,
                "architecture": architecture,
                "flavor": flavor,
                "asset_name": asset_name,
                "sha256": digest,
                "bytes": destination.stat().st_size,
                "virtual_size": candidate["virtual_size"],
                "build_runner": build_validation.get("runner"),
                "provenance_digest": provenance.get("digest"),
                "certificate_sha256": certificate_sha256,
                "signing_certificate_sha256": signing_certificate_sha256,
                "fallback_uki_sha256": fallback_uki_sha256,
                "azure_location": azure.get("location"),
                "azure_vm_size": azure.get("vm_size"),
                "derived_vhd_sha256": azure.get("derived_vhd_sha256"),
                "derived_vhd_bytes": derived_vhd_bytes,
                "derived_vhd_current_size": derived_vhd_current_size,
                "azure_image_version_id": azure.get("image_version_id"),
            }
        )

    write_json(
        output / "publish-manifest.json",
        {
            "schema": 1,
            "release_tag": args.release_tag,
            "source_commit": source_commit,
            "certificate_sha256": release_certificate_sha256,
            "signing_certificate_sha256": release_signing_certificate_sha256,
            "signing_provider": release_signing_provider,
            "assets": staged,
        },
    )

    lines = [
        "Azure Linux 4.0 generalized Gen2 images built from the accepted source commit "
        f"`{source_commit}`. Every published QCOW2 passed hosted structural validation and "
        "protected-environment native validation on a matching Azure architecture.",
        "",
        f"All UKIs are trusted through enrolled leaf SHA-256 `{release_certificate_sha256}`.",
        f"Artifact Signing leaf certificate SHA-256: `{release_signing_certificate_sha256}`.",
        "",
        "| Asset | SHA-256 | UKI SHA-256 | Bytes | Azure validation | Derived VHD evidence (not published) |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for item in staged:
        lines.append(
            f"| `{item['asset_name']}` | `{item['sha256']}` | `{item['fallback_uki_sha256']}` | {item['bytes']} | "
            f"`{item['azure_location']}` / `{item['azure_vm_size']}` | "
            f"`{item['derived_vhd_sha256']}`; current "
            f"{item['derived_vhd_current_size']} bytes; file "
            f"{item['derived_vhd_bytes']} bytes |"
        )
    lines.extend(
        [
            "",
            "The **full** images boot systemd and use cloud-init for account/key provisioning, "
            "WALinuxAgent for Azure Ready/extensions, and `sshd.service`. The **core** images "
            "boot `zvminit`, provision through `azagent`, and directly supervise OpenSSH. "
            "Core therefore requires a public SSH key in the Azure provisioning profile.",
            "",
            "Acceptance required signed UKIs, Azure Trusted Launch with Secure Boot and vTPM, "
            "the exact signer in UEFI db, kernel lockdown, "
            "module trust, key-only SSH, agent Ready, runtime architecture/flavor identity, root growth on an enlarged OS disk, temporary-resource-disk policy, managed-data-disk policy, and reboot/reconnect. Candidate and derived-VHD hashes were checked at every "
            "handoff; temporary VHDs and Azure resources were deleted.",
            "",
            "**No checksum sidecar assets are published**; SHA-256 digests are recorded only "
            "in these notes and the workflow job summary.",
            "",
            "Internal provenance bindings:",
            "",
        ]
    )
    for item in staged:
        lines.append(
            f"- `{item['asset_name']}`: provenance `{item['provenance_digest']}`; "
            f"hosted build on `{item['build_runner']}`"
        )
    args.notes.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    candidate = commands.add_parser("candidate")
    candidate.add_argument("--key", required=True)
    candidate.add_argument("--architecture", required=True)
    candidate.add_argument("--flavor", required=True)
    candidate.add_argument("--asset", type=Path, required=True)
    candidate.add_argument("--validated-sha256", required=True)
    candidate.add_argument("--virtual-size", type=int, required=True)
    candidate.add_argument("--source-commit", required=True)
    candidate.add_argument("--provenance-dir", type=Path, required=True)
    candidate.add_argument("--runner", required=True)
    candidate.add_argument("--run-id", required=True)
    candidate.add_argument("--run-attempt", required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.set_defaults(function=candidate_command)

    verify = commands.add_parser("verify-candidate")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--asset", type=Path, required=True)
    verify.add_argument("--key", required=True)
    verify.add_argument("--source-commit", required=True)
    verify.set_defaults(function=verify_candidate_command)

    verify_vhd = commands.add_parser("verify-vhd")
    verify_vhd.add_argument("--info", type=Path, required=True)
    verify_vhd.add_argument("--vhd", type=Path, required=True)
    verify_vhd.set_defaults(function=verify_vhd_command)

    azure = commands.add_parser("azure-result")
    azure.add_argument("--manifest", type=Path, required=True)
    azure.add_argument("--asset", type=Path, required=True)
    azure.add_argument("--vhd", type=Path, required=True)
    azure.add_argument("--vhd-current-size", type=int, required=True)
    azure.add_argument("--key", required=True)
    azure.add_argument("--source-commit", required=True)
    azure.add_argument("--location", required=True)
    azure.add_argument("--vm-size", required=True)
    azure.add_argument("--resource-group", required=True)
    azure.add_argument("--image-version-id", required=True)
    azure.add_argument("--uefi-request", type=Path, required=True)
    azure.add_argument("--uefi-response", type=Path, required=True)
    azure.add_argument("--run-id", required=True)
    azure.add_argument("--run-attempt", required=True)
    azure.add_argument("--output", type=Path, required=True)
    azure.set_defaults(function=azure_result_command)

    stage = commands.add_parser("stage")
    stage.add_argument("--candidates", type=Path, required=True)
    stage.add_argument("--azure-results", type=Path, required=True)
    stage.add_argument("--source-commit", required=True)
    stage.add_argument("--release-tag", required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--notes", type=Path, required=True)
    stage.set_defaults(function=stage_command)
    return result


def main() -> None:
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
