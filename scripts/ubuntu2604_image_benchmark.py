#!/usr/bin/env python3
"""Repeatable host benchmark for the pinned Ubuntu 26.04 arm64 bare-metal image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA = 1
ARCHITECTURE = "aarch64"
UBUNTU_ARCHITECTURE = "arm64"
FLAVOR = "baremetal"
OPTIMIZE = "ReleaseSafe"
VIRTUAL_SIZE = 5 * 1024 * 1024 * 1024
MINIMUM_FREE_DISK = 30 * 1024 * 1024 * 1024
MEASURED_RUNS = 3
SOURCE_NAME = "ubuntu-26.04-server-cloudimg-arm64.img"
SOURCE_SHA256 = "3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba"
MANIFEST_NAME = "ubuntu-26.04-server-cloudimg-arm64.manifest"
MANIFEST_SHA256 = "2889120db0432e8029f8f01622efb40ce964e434ba2c81e98937ad1e2616e4f5"
SUMS_SHA256 = "d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36"
SUMS_SIGNATURE_SHA256 = (
    "2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed"
)
DEBZ_API_COMMIT = "beac3f20dd93fd98863af71e8fe621d47db663f6"
CANONICAL_FINGERPRINT = "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81"
ASSET_NAME = "Ubuntu-26.04-aarch64.baremetal.qcow2"
RAW_ASSET_NAME = "Ubuntu-26.04-aarch64.baremetal.raw"
PACKAGE_ROOTS = (
    "ubuntu-minimal",
    "linux-image-7.0.0-2015-nvidia-bos-64k",
    "linux-modules-7.0.0-2015-nvidia-bos-64k",
    "initramfs-tools",
    "openssh-server",
    "sudo",
    "ca-certificates",
)
PHASE_ORDER = (
    "input_acquisition",
    "source_qcow2_setup",
    *(f"debz_transaction:{package}" for package in PACKAGE_ROOTS),
    "debz_aggregate",
    "initramfs_ext4_import",
    "uki_assembly",
    "uki_signing",
    "qcow2_finalization",
    "final_image_validation",
    "raw_image_materialization",
    "provenance_output",
    "total_runtime",
)
TIMING_PHASES = {
    "input_acquisition",
    "source_qcow2_setup",
    "debz_transaction",
    "debz_aggregate",
    "initramfs_ext4_import",
    "uki_assembly",
    "uki_signing",
    "qcow2_finalization",
    "final_image_validation",
    "raw_image_materialization",
    "provenance_output",
    "total_runtime",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEBZ_SNAPSHOT_BASE = "https://snapshot.ubuntu.com/ubuntu/20260731T000000Z"
DEBZ_SUITES = ("resolute", "resolute-updates", "resolute-security")
DEBZ_COMPONENTS = ("main", "restricted", "universe", "multiverse")
DEBZ_REFRESH_SNAPSHOT = "repository-refresh-v2"
DEBZ_POLICY_SNAPSHOT = "repository-policy-v1"
DEBZ_AGGREGATE_SNAPSHOT = "multi-repository-v1"
DEBZ_UNBOUNDED_DEADLINE_MS = (1 << 63) - 1


class BenchmarkError(RuntimeError):
    """A benchmark prerequisite, execution, or validation failure."""


def fail(message: str) -> None:
    raise BenchmarkError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON document is not an object: {path}")
    return value


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not a lowercase SHA-256")
    return value


def regular_file(
    path: Path,
    label: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a non-symlink regular file: {path}")
    if metadata.st_size <= 0:
        fail(f"{label} is empty: {path}")
    digest = sha256(path)
    if expected_sha256 is not None and digest != expected_sha256:
        fail(f"{label} SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    return {"path": str(path.resolve()), "bytes": metadata.st_size, "sha256": digest}


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha256sums", type=Path, required=True)
    parser.add_argument("--sha256sums-signature", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--debz-cache", type=Path, required=True)
    parser.add_argument("--debz-input-dir", type=Path, required=True)
    parser.add_argument("--debz-lock-dir", type=Path, required=True)
    parser.add_argument("--authorized-key", type=Path, required=True)
    parser.add_argument("--uki-stub", type=Path, required=True)
    parser.add_argument("--signing-certificate", type=Path, required=True)
    parser.add_argument("--signing-certificate-sha256", required=True)
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-key", type=Path)
    signing.add_argument("--sign-command", type=Path)
    parser.add_argument("--sign-command-arg")
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--zig-global-cache", type=Path, required=True)
    parser.add_argument(
        "--acceptance-command",
        type=Path,
        help=(
            "optional executable bare-metal boot harness; receives the image "
            "through VMIZ_UBUNTU2604_IMAGE"
        ),
    )
    parser.add_argument("--keep-images", action="store_true")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    args = argument_parser().parse_args(argv)
    if SHA256_RE.fullmatch(args.signing_certificate_sha256) is None:
        argument_parser().error(
            "--signing-certificate-sha256 must be a lowercase SHA-256"
        )
    if args.sign_command_arg is not None and args.sign_command is None:
        argument_parser().error("--sign-command-arg requires --sign-command")
    if args.sign_command is not None and not args.sign_command.is_absolute():
        argument_parser().error("--sign-command must be absolute")
    args.output_root = Path(os.path.abspath(args.output_root))
    for name in (
        "source",
        "sha256sums",
        "sha256sums_signature",
        "manifest",
        "debz_cache",
        "debz_input_dir",
        "debz_lock_dir",
        "authorized_key",
        "uki_stub",
        "signing_certificate",
        "signing_key",
        "sign_command",
        "zig",
        "zig_global_cache",
        "acceptance_command",
    ):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.resolve())
    return args


def prepare_session_dir(path: Path) -> Path:
    if path.name in {"", ".", ".."}:
        fail("output root must name a new directory")
    parent = path.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_dir():
        fail("output root parent must be a real directory")
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        fail(f"output root must not already exist: {candidate}")
    candidate.mkdir(mode=0o755)
    return candidate


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def require_run_path(path: Path, run_dir: Path, expected_relative: str) -> Path:
    try:
        resolved_run = run_dir.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        fail(f"unsafe benchmark cleanup path: {path}")
    if run_dir.is_symlink():
        fail(f"unsafe benchmark cleanup path: {path}")
    expected = resolved_run / expected_relative
    if resolved != expected or not is_within(resolved, resolved_run):
        fail(f"benchmark cleanup escaped its run directory: {path}")
    return resolved


def path_exists_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def cleanup_decisions(
    run_dir: Path,
    image: Path,
    raw_output: Path,
    work_dir: Path,
    *,
    keep_images: bool,
) -> list[tuple[str, Path]]:
    decisions: list[tuple[str, Path]] = []
    if path_exists_or_symlink(image) and not keep_images:
        decisions.append(
            (
                "file",
                require_run_path(image, run_dir, f"artifact/{ASSET_NAME}"),
            )
        )
    if path_exists_or_symlink(raw_output) and not keep_images:
        decisions.append(
            (
                "file",
                require_run_path(
                    raw_output,
                    run_dir,
                    f"artifact/{RAW_ASSET_NAME}",
                ),
            )
        )
    if path_exists_or_symlink(work_dir):
        decisions.append(("tree", require_run_path(work_dir, run_dir, "work")))
    return decisions


def cleanup_run(
    run_dir: Path,
    image: Path,
    raw_output: Path,
    work_dir: Path,
    *,
    keep_images: bool,
) -> list[str]:
    removed: list[str] = []
    for kind, target in cleanup_decisions(
        run_dir,
        image,
        raw_output,
        work_dir,
        keep_images=keep_images,
    ):
        if kind == "file":
            target.unlink()
        else:
            shutil.rmtree(target)
        removed.append(target.relative_to(run_dir.resolve()).as_posix())
    return removed


def verify_cache_objects(directory: Path, label: str) -> list[dict[str, object]]:
    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        fail(f"warm debz cache is missing {label}: {directory}")
    records: list[dict[str, object]] = []
    for path in entries:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or SHA256_RE.fullmatch(path.name) is None
        ):
            fail(f"{label} contains a non-CAS entry: {path}")
        digest = sha256(path)
        if digest != path.name:
            fail(f"{label} object digest does not match its name: {path}")
        records.append(
            {"path": path.name, "bytes": metadata.st_size, "sha256": digest}
        )
    if not records:
        fail(f"warm debz cache has no {label} objects")
    return records


def verify_warm_cache(cache: Path) -> dict[str, object]:
    try:
        metadata = cache.lstat()
    except FileNotFoundError:
        fail(f"debz cache is missing: {cache}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("debz cache must be a non-symlink directory")
    metadata_objects = verify_cache_objects(
        cache / "metadata-v1" / "objects", "metadata"
    )
    metadata_by_digest = {
        str(item["path"]): item for item in metadata_objects
    }
    package_objects = verify_cache_objects(
        cache / "packages-v1" / "objects", "package"
    )
    manifests = cache / "metadata-v1" / "manifests"
    try:
        manifest_entries = sorted(manifests.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        fail("warm debz cache is missing metadata manifests")
    manifest_records = []
    for path in manifest_entries:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or SHA256_RE.fullmatch(path.name) is None
        ):
            fail(f"metadata manifest is not a CAS-keyed regular file: {path}")
        if metadata.st_size <= 0 or metadata.st_size > 4096:
            fail(f"metadata manifest size is invalid: {path}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            fail(f"cannot read metadata manifest {path}: {error}")
        if len(lines) != 8 or lines[0] != "debz-metadata-manifest-v1":
            fail(f"metadata manifest has the wrong schema: {path}")
        fields = {}
        for line in lines[1:]:
            name, separator, value = line.partition("=")
            if not separator or name in fields:
                fail(f"metadata manifest has invalid fields: {path}")
            fields[name] = value
        if set(fields) != {
            "repository",
            "snapshot",
            "digest",
            "size",
            "verification",
            "verified-at",
            "verifier-input",
        }:
            fail(f"metadata manifest has unexpected fields: {path}")
        repository = require_sha256(
            fields["repository"], f"metadata manifest {path.name} repository"
        )
        snapshot = fields["snapshot"]
        if (
            not snapshot
            or len(snapshot) > 255
            or any(
                not (
                    character.isascii()
                    and (character.isalnum() or character in "-_.")
                )
                for character in snapshot
            )
        ):
            fail(f"metadata manifest {path.name} snapshot is invalid")
        if path.name != debz_manifest_name(repository, snapshot):
            fail(f"metadata manifest filename does not match its cache key: {path}")
        object_digest = require_sha256(
            fields["digest"], f"metadata manifest {path.name} object"
        )
        try:
            object_size = int(fields["size"])
            int(fields["verified-at"])
        except ValueError:
            fail(f"metadata manifest has invalid numeric fields: {path}")
        if object_size <= 0:
            fail(f"metadata manifest has invalid object size: {path}")
        if fields["verification"] not in {
            "unauthenticated_release",
            "in_release",
            "detached_release",
            "trusted_snapshot",
        }:
            fail(f"metadata manifest has invalid verification mode: {path}")
        verifier = fields["verifier-input"]
        if verifier != "-":
            require_sha256(
                verifier, f"metadata manifest {path.name} verifier input"
            )
        referenced = metadata_by_digest.get(object_digest)
        if referenced is None:
            fail(
                f"metadata manifest {path.name} references missing object "
                f"{object_digest}"
            )
        if object_size != referenced["bytes"]:
            fail(
                f"metadata manifest {path.name} object size differs from "
                f"{object_digest}"
            )
        manifest_records.append(
            {
                "path": path.name,
                "bytes": metadata.st_size,
                "sha256": sha256(path),
                "repository": repository,
                "snapshot": snapshot,
                "object_sha256": object_digest,
                "object_bytes": object_size,
            }
        )
    if not manifest_records:
        fail("warm debz cache has no metadata manifests")
    public = {
        "schema": SCHEMA,
        "type": "vmiz-debz-cache-inventory",
        "metadata_objects": len(metadata_objects),
        "metadata_bytes": sum(item["bytes"] for item in metadata_objects),
        "metadata_manifests": len(manifest_records),
        "package_objects": len(package_objects),
        "package_bytes": sum(item["bytes"] for item in package_objects),
        "object_inventory_sha256": canonical_digest(
            {
                "metadata": metadata_objects,
                "packages": package_objects,
            }
        ),
        "manifest_inventory_sha256": canonical_digest(manifest_records),
        "inventory_sha256": canonical_digest(
            {
                "metadata": metadata_objects,
                "manifests": manifest_records,
                "packages": package_objects,
            }
        ),
    }
    public["_package_object_names"] = {item["path"] for item in package_objects}
    public["_metadata_manifests"] = {
        item["path"]: item for item in manifest_records
    }
    return public


def debz_hash_part(digest: Any, value: str) -> None:
    encoded = value.encode()
    digest.update(struct.pack(">Q", len(encoded)))
    digest.update(encoded)


def debz_hash_int(digest: Any, value: int) -> None:
    digest.update(struct.pack(">q", value))


# Mirrors the pinned debz repository_policy identity: Signed-By is deliberately
# part of the key, while config file location and credentials are not.
def debz_repository_id(
    *,
    suite: str,
    component: str,
    keyring_path: Path,
) -> str:
    digest = hashlib.sha256()
    for value in (
        "enabled",
        DEBZ_SNAPSHOT_BASE,
        suite,
        component,
        UBUNTU_ARCHITECTURE,
        str(keyring_path),
    ):
        debz_hash_part(digest, value)
    debz_hash_int(digest, 500)
    for value in ("", "immutable_url", "", "direct"):
        debz_hash_part(digest, value)
    for value in (
        DEBZ_UNBOUNDED_DEADLINE_MS,
        DEBZ_UNBOUNDED_DEADLINE_MS,
        DEBZ_UNBOUNDED_DEADLINE_MS,
    ):
        debz_hash_int(digest, value)
    return digest.hexdigest()


def debz_manifest_name(repository: str, snapshot: str) -> str:
    return hashlib.sha256(
        repository.encode() + b"\0" + snapshot.encode()
    ).hexdigest()


def benchmark_cache_requirements(input_dir: Path) -> list[dict[str, str]]:
    keyring = input_dir.resolve() / "ubuntu-archive-keyring.gpg"
    repositories = sorted(
        debz_repository_id(
            suite=suite,
            component=component,
            keyring_path=keyring,
        )
        for suite in DEBZ_SUITES
        for component in DEBZ_COMPONENTS
    )
    requirements = []
    for repository in repositories:
        for phase, snapshot in (
            ("repository-refresh", DEBZ_REFRESH_SNAPSHOT),
            ("repository-policy", DEBZ_POLICY_SNAPSHOT),
        ):
            requirements.append(
                {
                    "phase": phase,
                    "repository": repository,
                    "snapshot": snapshot,
                    "filename": debz_manifest_name(repository, snapshot),
                }
            )
    configuration = hashlib.sha256()
    debz_hash_part(configuration, "debz-multi-repository-configuration-v1")
    for repository in repositories:
        debz_hash_part(configuration, repository)
    configuration_id = configuration.hexdigest()
    requirements.append(
        {
            "phase": "repository-aggregate",
            "repository": configuration_id,
            "snapshot": DEBZ_AGGREGATE_SNAPSHOT,
            "filename": debz_manifest_name(
                configuration_id, DEBZ_AGGREGATE_SNAPSHOT
            ),
        }
    )
    return requirements


def verify_benchmark_cache(cache: Path, input_dir: Path) -> dict[str, object]:
    inventory = verify_warm_cache(cache)
    manifests = inventory["_metadata_manifests"]
    for requirement in benchmark_cache_requirements(input_dir):
        manifest = manifests.get(requirement["filename"])
        if manifest is None:
            fail(
                "warm debz cache is missing metadata manifest "
                f"{requirement['filename']} for phase {requirement['phase']}, "
                f"repository {requirement['repository']}, snapshot "
                f"{requirement['snapshot']}; repository identity binds Signed-By "
                f"{input_dir.resolve() / 'ubuntu-archive-keyring.gpg'}"
            )
        if (
            manifest["repository"] != requirement["repository"]
            or manifest["snapshot"] != requirement["snapshot"]
        ):
            fail(
                f"warm debz cache metadata manifest {requirement['filename']} "
                f"does not bind phase {requirement['phase']} to repository "
                f"{requirement['repository']} and snapshot "
                f"{requirement['snapshot']}"
            )
    return inventory


def lock_filename(package: str) -> str:
    return f"debz-exact-lock-{package}-{UBUNTU_ARCHITECTURE}.json"


def validate_package(entry: object, label: str) -> dict[str, object]:
    if not isinstance(entry, dict):
        fail(f"{label} package entry is not an object")
    result: dict[str, object] = {}
    for field in ("name", "version", "architecture"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            fail(f"{label} package {field} is invalid")
        result[field] = value
    result["sha256"] = require_sha256(entry.get("sha256"), f"{label} package hash")
    if result["architecture"] not in {UBUNTU_ARCHITECTURE, "all"}:
        fail(f"{label} contains a foreign package architecture")
    return result


def verify_lock_set(
    lock_dir: Path,
    package_object_names: set[str],
) -> dict[str, object]:
    if lock_dir.is_symlink() or not lock_dir.is_dir():
        fail("debz lock directory must be a non-symlink directory")
    locks = []
    final_closure: list[dict[str, object]] = []
    for package in PACKAGE_ROOTS:
        path = lock_dir / lock_filename(package)
        file_record = regular_file(path, f"{package} exact lock")
        document = read_json(path)
        if (
            document.get("schema")
            != "https://debz.dev/schema/exact-closure-lock-v1"
            or document.get("version") != 1
            or document.get("target_architecture") != UBUNTU_ARCHITECTURE
        ):
            fail(f"{package} exact lock has the wrong schema or architecture")
        digest = require_sha256(
            document.get("digest_sha256"), f"{package} exact-lock digest"
        )
        packages = document.get("packages")
        if not isinstance(packages, list) or not packages:
            fail(f"{package} exact lock has an empty closure")
        closure = [
            validate_package(entry, f"{package} exact lock") for entry in packages
        ]
        identities = [
            (item["name"], item["version"], item["architecture"]) for item in closure
        ]
        if len(set(identities)) != len(identities):
            fail(f"{package} exact lock has duplicate package identities")
        if not any(item["name"] == package for item in closure):
            fail(f"{package} exact lock does not contain its requested package")
        missing = sorted(
            item["sha256"]
            for item in closure
            if item["sha256"] not in package_object_names
        )
        if missing:
            fail(
                f"{package} exact lock has {len(missing)} package cache miss(es); "
                f"first missing object: {missing[0]}"
            )
        closure.sort(
            key=lambda item: (
                str(item["name"]),
                str(item["architecture"]),
                str(item["version"]),
                str(item["sha256"]),
            )
        )
        locks.append(
            {
                "package": package,
                "filename": path.name,
                "file_sha256": file_record["sha256"],
                "digest_sha256": digest,
                "packages": len(closure),
            }
        )
        final_closure = closure
    return {
        "schema": SCHEMA,
        "type": "vmiz-ubuntu2604-benchmark-lock-set",
        "locks": locks,
        "final_closure": final_closure,
        "closure_sha256": canonical_digest(final_closure),
    }


def load_timing(path: Path) -> dict[str, object]:
    document = read_json(path)
    if set(document) != {
        "schema",
        "type",
        "clock",
        "duration_unit",
        "status",
        "failed_phase",
        "failed_item",
        "error_name",
        "phases",
    }:
        fail("timing JSON has unexpected fields")
    if (
        document.get("schema") != 1
        or document.get("type") != "vmiz-ubuntu2604-image-phase-timing"
        or document.get("clock") != "monotonic"
        or document.get("duration_unit") != "nanoseconds"
        or document.get("status") != "success"
        or document.get("failed_phase") is not None
        or document.get("failed_item") is not None
        or document.get("error_name") is not None
    ):
        fail("timing JSON does not record a successful schema-v1 run")
    phases = document.get("phases")
    if not isinstance(phases, list) or not phases:
        fail("timing JSON has no phases")
    values: dict[str, int] = {}
    debz_items = []
    for index, phase in enumerate(phases):
        if not isinstance(phase, dict) or set(phase) != {
            "name",
            "item",
            "elapsed_ns",
            "outcome",
            "error_name",
        }:
            fail(f"timing phase {index} has unexpected fields")
        name = phase.get("name")
        item = phase.get("item")
        elapsed = phase.get("elapsed_ns")
        outcome = phase.get("outcome")
        if name not in TIMING_PHASES:
            fail(f"timing phase {index} has an unknown name")
        if type(elapsed) is not int or elapsed < 0:
            fail(f"timing phase {index} has an invalid elapsed_ns")
        if outcome not in {"success", "skipped"} or phase.get("error_name") is not None:
            fail(f"timing phase {index} did not succeed")
        key = str(name)
        if name == "debz_transaction":
            if item not in PACKAGE_ROOTS:
                fail("timing JSON has an unknown debz package item")
            debz_items.append(item)
            key = f"{name}:{item}"
        elif item is not None:
            fail(f"timing phase {name} unexpectedly has an item")
        if key in values:
            fail(f"timing JSON contains duplicate phase {key}")
        if key == "raw_image_materialization" and outcome != "success":
            fail("timing JSON raw_image_materialization was not successful")
        values[key] = elapsed
    if tuple(debz_items) != PACKAGE_ROOTS:
        fail("timing JSON does not contain the exact ordered package transactions")
    missing = [phase for phase in PHASE_ORDER if phase not in values]
    if missing:
        fail(f"timing JSON is missing phase {missing[0]}")
    if phases[-1].get("name") != "total_runtime":
        fail("timing JSON total_runtime is not last")
    return {"document": document, "values": values}


def median_int(values: Iterable[int]) -> int:
    ordered = sorted(values)
    if not ordered:
        fail("cannot calculate a median of no values")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def proc_snapshot(root_pid: int) -> dict[tuple[int, str], dict[str, int]]:
    processes: dict[int, tuple[int, str]] = {}
    for child in Path("/proc").iterdir():
        if not child.name.isdigit():
            continue
        try:
            text = (child / "stat").read_text(encoding="ascii")
            close = text.rfind(")")
            fields = text[close + 2 :].split()
            processes[int(child.name)] = (int(fields[1]), fields[19])
        except (OSError, ValueError, IndexError):
            continue
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _) in processes.items():
            if parent in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    result = {}
    for pid in descendants:
        if pid not in processes:
            continue
        try:
            status_text = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            rss_kib = 0
            for line in status_text.splitlines():
                if line.startswith("VmRSS:"):
                    rss_kib = int(line.split()[1])
                    break
            io_values = {"read_bytes": 0, "write_bytes": 0}
            for line in Path(f"/proc/{pid}/io").read_text(
                encoding="ascii"
            ).splitlines():
                name, value = line.split(":", 1)
                if name in io_values:
                    io_values[name] = int(value.strip())
            result[(pid, processes[pid][1])] = {
                "rss_bytes": rss_kib * 1024,
                **io_values,
            }
        except (OSError, ValueError):
            continue
    return result


def run_measured_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> dict[str, object]:
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    peak_rss = 0
    per_process_io: dict[tuple[int, str], tuple[int, int]] = {}
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        while process.poll() is None:
            snapshot = proc_snapshot(process.pid)
            peak_rss = max(
                peak_rss,
                sum(item["rss_bytes"] for item in snapshot.values()),
            )
            for identity, item in snapshot.items():
                previous = per_process_io.get(identity, (0, 0))
                per_process_io[identity] = (
                    max(previous[0], item["read_bytes"]),
                    max(previous[1], item["write_bytes"]),
                )
            time.sleep(0.05)
        return_code = process.returncode
    finished = time.monotonic_ns()
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "schema": SCHEMA,
        "type": "vmiz-host-resource-timing",
        "status": "success" if return_code == 0 else "failure",
        "exit_code": return_code,
        "wall_ns": finished - started,
        "user_ns": int((usage_after.ru_utime - usage_before.ru_utime) * 1e9),
        "system_ns": int((usage_after.ru_stime - usage_before.ru_stime) * 1e9),
        "peak_rss_bytes": peak_rss or None,
        "read_bytes": sum(item[0] for item in per_process_io.values())
        if per_process_io
        else None,
        "write_bytes": sum(item[1] for item in per_process_io.values())
        if per_process_io
        else None,
        "block_inputs": usage_after.ru_inblock - usage_before.ru_inblock,
        "block_outputs": usage_after.ru_oublock - usage_before.ru_oublock,
        "io_bytes_source": (
            "linux-proc-descendant-sampling" if per_process_io else "unavailable"
        ),
    }


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> None:
    with log_path.open("wb") as log:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        fail(f"command failed ({result.returncode}); see {log_path}")


def validate_image_info(path: Path) -> dict[str, object]:
    info = read_json(path)
    if info.get("format") != "qcow2":
        fail("benchmark output is not QCOW2")
    if info.get("virtual-size") != VIRTUAL_SIZE:
        fail("benchmark output does not have the exact 5 GiB virtual size")
    if info.get("backing-filename") or info.get("full-backing-filename"):
        fail("benchmark output unexpectedly has a backing file")
    data = (info.get("format-specific") or {}).get("data") if isinstance(
        info.get("format-specific"), dict
    ) else None
    if not isinstance(data, dict) or data.get("compression-type") != "zstd":
        fail("benchmark output is not a standalone zstd QCOW2")
    return {
        "format": "qcow2",
        "virtual_size": VIRTUAL_SIZE,
        "compression_type": "zstd",
        "backing_file": None,
    }


def validate_raw_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"raw benchmark output is missing: {path}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"raw benchmark output must be a non-symlink regular file: {path}")
    if metadata.st_size != VIRTUAL_SIZE:
        fail("raw benchmark output does not have the exact 5 GiB virtual size")
    return metadata


def validate_raw_output(path: Path, info_path: Path) -> dict[str, object]:
    metadata = validate_raw_file(path)
    info = read_json(info_path)
    if (
        set(info)
        != {
            "filename",
            "format",
            "virtual-size",
            "actual-size",
            "subformat",
            "backing-filename",
            "format-specific",
        }
        or info.get("filename") != str(path)
        or info.get("format") != "raw"
        or info.get("virtual-size") != VIRTUAL_SIZE
        or info.get("actual-size") != VIRTUAL_SIZE
        or info.get("subformat") is not None
        or info.get("backing-filename") is not None
        or info.get("format-specific") is not None
    ):
        fail("raw benchmark output metadata is invalid")
    return {
        "filename": RAW_ASSET_NAME,
        "format": "raw",
        "bytes": metadata.st_size,
        "virtual_size": VIRTUAL_SIZE,
        "structural_validation": "vmiz-check-and-info",
        "byte_hash_recorded": False,
        "byte_reproducibility_compared": False,
    }


def validate_transaction(
    path: Path,
    binding: dict[str, object],
    lock_digest: str,
    package: str,
) -> tuple[dict[str, str], dict[str, str]]:
    file_digest = sha256(path)
    if file_digest != binding.get("sha256"):
        fail(f"{package} transaction provenance file hash mismatch")
    document = read_json(path)
    final = document.get("final_verification")
    provenance_digest = require_sha256(
        binding.get("digest_sha256"), f"{package} transaction digest"
    )
    if (
        document.get("schema") != "https://debz.dev/schema/transaction-result-v1"
        or document.get("version") != 1
        or document.get("target_architecture") != UBUNTU_ARCHITECTURE
        or document.get("lock_sha256") != lock_digest
        or document.get("digest_sha256") != provenance_digest
        or document.get("outcome") != "succeeded"
        or not isinstance(final, dict)
        or final.get("status") != "exact_match"
    ):
        fail(f"{package} transaction provenance does not prove exact success")
    return (
        {
            "package": package,
            "digest_sha256": provenance_digest,
            "lock_sha256": lock_digest,
        },
        {
            "package": package,
            "filename": path.name,
            "file_sha256": file_digest,
        },
    )


def validate_provenance(
    root: Path,
    lock_set: dict[str, object],
    *,
    certificate_sha256: str,
) -> tuple[dict[str, object], list[dict[str, str]]]:
    if root.is_symlink() or not root.is_dir():
        fail("provenance directory is missing or unsafe")
    build = read_json(root / "ubuntu2604-build-provenance.json")
    expected_fields = {
        "schema",
        "type",
        "architecture",
        "flavor",
        "release",
        "virtual_size",
        "minimum_root_free_bytes",
        "validated_root_free_bytes",
        "snapshot",
        "canonical_key_fingerprint",
        "sha256sums_signature_verified",
        "artifacts",
        "debz",
    }
    if set(build) != expected_fields:
        fail("Ubuntu build provenance has unexpected fields")
    if (
        build.get("schema") != 1
        or build.get("type") != "vmiz-ubuntu2604-build-provenance"
        or build.get("architecture") != ARCHITECTURE
        or build.get("flavor") != FLAVOR
        or build.get("release") != "26.04"
        or build.get("virtual_size") != VIRTUAL_SIZE
        or build.get("snapshot")
        != {
            "id": "release-20260731",
            "base_url": (
                "https://cloud-images.ubuntu.com/releases/"
                "26.04/release-20260731/"
            ),
        }
        or build.get("canonical_key_fingerprint") != CANONICAL_FINGERPRINT
        or build.get("sha256sums_signature_verified") is not True
    ):
        fail("Ubuntu build provenance identity is invalid")
    minimum_free = build.get("minimum_root_free_bytes")
    validated_free = build.get("validated_root_free_bytes")
    if (
        type(minimum_free) is not int
        or type(validated_free) is not int
        or minimum_free <= 0
        or validated_free < minimum_free
        or validated_free >= VIRTUAL_SIZE
    ):
        fail("Ubuntu build provenance free-space constraint is invalid")
    expected_artifacts = {
        "sha256sums": ("SHA256SUMS", SUMS_SHA256),
        "sha256sums_signature": ("SHA256SUMS.gpg", SUMS_SIGNATURE_SHA256),
        "source_image": (SOURCE_NAME, SOURCE_SHA256),
        "image_manifest": (MANIFEST_NAME, MANIFEST_SHA256),
    }
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(expected_artifacts):
        fail("Ubuntu source artifact provenance is not exact")
    for name, (filename, digest) in expected_artifacts.items():
        binding = artifacts[name]
        if not isinstance(binding, dict):
            fail(f"Ubuntu {name} binding is invalid")
        required = {"filename", "sha256", "role"} if name == "source_image" else {
            "filename",
            "sha256",
        }
        if (
            set(binding) != required
            or binding.get("filename") != filename
            or binding.get("sha256") != digest
        ):
            fail(f"Ubuntu {name} binding is invalid")
        if name == "source_image" and binding.get("role") != "signed-gpt-esp-substrate":
            fail("Ubuntu source image role is invalid")
        if name != "source_image":
            bound_file = root / filename
            if sha256(bound_file) != digest:
                fail(f"Ubuntu {name} provenance file hash mismatch")
    debz = build.get("debz")
    if (
        not isinstance(debz, dict)
        or set(debz) != {"api_commit", "baseline", "package_roots", "transactions"}
        or debz.get("api_commit") != DEBZ_API_COMMIT
        or debz.get("baseline")
        != {
            "source": "empty-debz-root",
            "enforcement": "exact-final-closure",
        }
        or debz.get("package_roots") != list(PACKAGE_ROOTS)
    ):
        fail("Ubuntu debz package roots are not exact")
    transactions = debz.get("transactions")
    if not isinstance(transactions, list) or len(transactions) != len(PACKAGE_ROOTS):
        fail("Ubuntu debz transaction count is not exact")
    expected_locks = {
        item["package"]: item for item in lock_set["locks"]  # type: ignore[index]
    }
    transaction_contracts = []
    transaction_files = []
    for package, transaction in zip(PACKAGE_ROOTS, transactions, strict=True):
        if not isinstance(transaction, dict) or transaction.get("package") != package:
            fail("Ubuntu debz transactions are not stably ordered")
        lock_binding = transaction.get("exact_lock")
        provenance_binding = transaction.get("transaction_provenance")
        if not isinstance(lock_binding, dict) or not isinstance(
            provenance_binding, dict
        ):
            fail(f"{package} transaction bindings are absent")
        expected_lock = expected_locks[package]
        if (
            lock_binding.get("filename") != expected_lock["filename"]
            or lock_binding.get("sha256") != expected_lock["file_sha256"]
            or lock_binding.get("digest_sha256") != expected_lock["digest_sha256"]
            or sha256(root / str(lock_binding["filename"]))
            != expected_lock["file_sha256"]
        ):
            fail(f"{package} output exact lock differs from the pinned input")
        lock_digest = str(expected_lock["digest_sha256"])
        if provenance_binding.get("lock_sha256") != lock_digest:
            fail(f"{package} transaction is not bound to its exact lock")
        transaction_contract, transaction_file = validate_transaction(
            root / str(provenance_binding.get("filename")),
            provenance_binding,
            lock_digest,
            package,
        )
        transaction_contracts.append(transaction_contract)
        transaction_files.append(transaction_file)
    boot = read_json(root / "ubuntu2604-boot-input-evidence.json")
    if (
        boot.get("schema") != 1
        or boot.get("type") != "vmiz-ubuntu2604-boot-input-evidence"
        or boot.get("architecture") != ARCHITECTURE
        or boot.get("package_lock")
        != "/var/lib/vmiz/ubuntu2604-package-lock.tsv"
        or not isinstance(boot.get("kernel_release"), str)
        or not str(boot["kernel_release"]).endswith("-nvidia-bos-64k")
    ):
        fail("bare-metal boot input evidence is invalid")
    package_lock_sha256 = require_sha256(
        boot.get("package_lock_sha256"), "embedded package inventory digest"
    )
    signing = read_json(root / "uki-signing-baremetal-aarch64.json")
    if (
        signing.get("schema") != 1
        or signing.get("type") != "vmiz-uki-signing"
        or signing.get("architecture") != ARCHITECTURE
        or signing.get("flavor") != FLAVOR
        or signing.get("certificate_sha256") != certificate_sha256
        or signing.get("signature_verification") != "success"
    ):
        fail("UKI signing provenance is invalid")
    stub = signing.get("uki_stub")
    if not isinstance(stub, dict):
        fail("UKI stub provenance is missing")
    stub_sha256 = require_sha256(stub.get("sha256"), "UKI stub digest")
    return (
        {
            "source_artifacts": expected_artifacts,
            "package_roots": list(PACKAGE_ROOTS),
            "lock_set_sha256": canonical_digest(lock_set["locks"]),
            "transaction_provenance": transaction_contracts,
            "closure_sha256": lock_set["closure_sha256"],
            "virtual_size": VIRTUAL_SIZE,
            "minimum_root_free_bytes": minimum_free,
            "validated_root_free_bytes": validated_free,
            "kernel_release": boot["kernel_release"],
            "embedded_package_inventory_sha256": package_lock_sha256,
            "signing": {
                "mode": signing.get("signer_mode"),
                "certificate_sha256": certificate_sha256,
                "uki_stub_sha256": stub_sha256,
                "signature_verification": "success",
            },
        },
        transaction_files,
    )


def compare_correctness(
    reference: dict[str, object],
    candidate: dict[str, object],
) -> None:
    if reference != candidate:
        fail("correctness evidence differs from the warm-up reference")


def build_summary(
    runs: list[dict[str, object]],
    *,
    source_commit: str,
    host: dict[str, object],
    cache_inventory: dict[str, object],
    lock_set: dict[str, object],
) -> dict[str, object]:
    measured = [run for run in runs if run["kind"] == "measured"]
    if len(measured) != MEASURED_RUNS:
        fail("summary requires exactly three measured runs")
    phase_medians = {
        phase: median_int(
            run["timing_values"][phase] for run in measured  # type: ignore[index]
        )
        for phase in PHASE_ORDER
    }
    resource_fields = (
        "wall_ns",
        "user_ns",
        "system_ns",
        "peak_rss_bytes",
        "read_bytes",
        "write_bytes",
        "block_inputs",
        "block_outputs",
    )
    resource_medians: dict[str, int | None] = {}
    for field in resource_fields:
        values = [run["resources"][field] for run in measured]  # type: ignore[index]
        resource_medians[field] = (
            median_int(value for value in values if isinstance(value, int))
            if all(isinstance(value, int) for value in values)
            else None
        )
    return {
        "schema": SCHEMA,
        "type": "vmiz-ubuntu2604-image-benchmark-summary",
        "status": "valid",
        "profile": {
            "source": SOURCE_NAME,
            "source_sha256": SOURCE_SHA256,
            "release": "26.04",
            "architecture": ARCHITECTURE,
            "flavor": FLAVOR,
            "optimization": OPTIMIZE,
            "virtual_size": VIRTUAL_SIZE,
            "warmup_runs": 1,
            "measured_runs": MEASURED_RUNS,
            "network_policy": "offline",
            "raw_image_materialization": "required",
        },
        "source_commit": source_commit,
        "host": host,
        "cache_inventory": {
            key: value
            for key, value in cache_inventory.items()
            if not key.startswith("_")
        },
        "package_lock_set": {
            "closure_sha256": lock_set["closure_sha256"],
            "locks": lock_set["locks"],
        },
        "medians": {
            "phase_elapsed_ns": phase_medians,
            "resources": {
                **resource_medians,
                "io_bytes_source": "linux-proc-descendant-sampling",
            },
        },
        "correctness": {
            "status": "identical",
            "reference_sha256": runs[0]["correctness_sha256"],
            "byte_hash_comparison": "not-applicable-no-image-byte-reproducibility-contract",
        },
        "runs": [
            {
                "name": run["name"],
                "kind": run["kind"],
                "evidence": run["evidence"],
                "image_sha256": run["image_sha256"],
                "image_bytes": run["image_bytes"],
                "raw_output": run["raw_output"],
                "cleanup": run["cleanup"],
            }
            for run in runs
        ],
    }


def format_seconds(nanoseconds: int | None) -> str:
    return "unavailable" if nanoseconds is None else f"{nanoseconds / 1e9:.3f} s"


def readable_summary(summary: dict[str, object]) -> str:
    medians = summary["medians"]  # type: ignore[index]
    phases = medians["phase_elapsed_ns"]  # type: ignore[index]
    resources = medians["resources"]  # type: ignore[index]
    lines = [
        "Ubuntu 26.04 aarch64 bare-metal ReleaseSafe image benchmark",
        "",
        "Status: valid",
        "Protocol: one warm-up followed by three measured offline runs",
        f"Source commit: {summary['source_commit']}",
        f"Median total phase time: {format_seconds(phases['total_runtime'])}",
        f"Median host wall time: {format_seconds(resources['wall_ns'])}",
        f"Median user time: {format_seconds(resources['user_ns'])}",
        f"Median system time: {format_seconds(resources['system_ns'])}",
        f"Median peak RSS: {resources['peak_rss_bytes']} bytes",
        f"Median sampled read bytes: {resources['read_bytes']}",
        f"Median sampled write bytes: {resources['write_bytes']}",
        "",
        "Phase medians:",
    ]
    for phase in PHASE_ORDER:
        lines.append(f"  {phase}: {format_seconds(phases[phase])}")
    lines.extend(
        [
            "",
            "Correctness: package name/version/hash closure, provenance, "
            "manifest, boot-input evidence, image structure, and acceptance "
            "result were identical.",
            "QCOW2 byte hashes are recorded and raw output metadata is retained. "
            "Image bytes are not compared because bare-metal output has no "
            "documented byte-reproducibility contract.",
            "",
        ]
    )
    return "\n".join(lines)


def git_output(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def preflight(
    args: argparse.Namespace,
    repo: Path,
    session: Path,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, str],
    str,
    dict[str, object],
]:
    if platform.system() != "Linux" or platform.machine() not in {"aarch64", "arm64"}:
        fail("the production benchmark requires a native aarch64 Linux host")
    if os.geteuid() != 0:
        fail("run the production benchmark as root for offline-root customization")
    if shutil.disk_usage(session).free < MINIMUM_FREE_DISK:
        fail("the benchmark output filesystem has less than 30 GiB free")
    inputs = {
        "source": regular_file(args.source, "source image", expected_sha256=SOURCE_SHA256),
        "sha256sums": regular_file(
            args.sha256sums, "SHA256SUMS", expected_sha256=SUMS_SHA256
        ),
        "sha256sums_signature": regular_file(
            args.sha256sums_signature,
            "SHA256SUMS signature",
            expected_sha256=SUMS_SIGNATURE_SHA256,
        ),
        "manifest": regular_file(
            args.manifest, "source manifest", expected_sha256=MANIFEST_SHA256
        ),
        "authorized_key": regular_file(args.authorized_key, "authorized key"),
        "uki_stub": regular_file(args.uki_stub, "aarch64 UKI stub"),
        "signing_certificate": regular_file(
            args.signing_certificate, "signing certificate"
        ),
        "zig": regular_file(args.zig, "Zig executable"),
    }
    if args.debz_input_dir.is_symlink() or not args.debz_input_dir.is_dir():
        fail("debz input directory must be a non-symlink directory")
    inputs["debz_repository_inputs"] = {
        "path": str(args.debz_input_dir.resolve()),
        "cache_identity": "stable-signed-by-path",
    }
    if not os.access(args.zig, os.X_OK):
        fail("Zig path is not executable")
    if args.signing_key is not None:
        regular_file(args.signing_key, "signing key")
        inputs["signing"] = {"mode": "local-key", "private_key_recorded": False}
    else:
        inputs["sign_command"] = regular_file(args.sign_command, "sign command")
        if not os.access(args.sign_command, os.X_OK):
            fail("sign command is not executable")
    if args.acceptance_command is not None:
        inputs["acceptance_command"] = regular_file(
            args.acceptance_command, "acceptance command"
        )
        if not os.access(args.acceptance_command, os.X_OK):
            fail("acceptance command is not executable")
    cache_inventory = verify_benchmark_cache(
        args.debz_cache, args.debz_input_dir
    )
    lock_set = verify_lock_set(
        args.debz_lock_dir,
        cache_inventory["_package_object_names"],  # type: ignore[arg-type]
    )
    version = subprocess.run(
        [str(args.zig), "version"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if version.returncode != 0 or version.stdout.strip() != "0.16.0":
        fail("benchmark requires Zig 0.16.0")
    host = {
        "system": platform.system(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "zig": version.stdout.strip(),
    }
    source_commit = git_output(repo, "rev-parse", "HEAD")
    if git_output(repo, "status", "--porcelain", "--untracked-files=no"):
        fail("benchmark source worktree has tracked modifications")
    if args.zig_global_cache.exists() and (
        args.zig_global_cache.is_symlink() or not args.zig_global_cache.is_dir()
    ):
        fail("Zig global cache must be a non-symlink directory")
    args.zig_global_cache.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(args.zig_global_cache.resolve())
    env["ZIG_LOCAL_CACHE_DIR"] = str((session / "zig-local-cache").resolve())
    compile_log = session / "preflight-build.log"
    run_logged(
        [
            str(args.zig),
            "build",
            "-Doptimize=ReleaseSafe",
            "-Dubuntu2604-arch=aarch64",
            "-Dubuntu2604-flavor=baremetal",
            "install-vmiz",
            "check-generalized-ubuntu2604",
        ],
        cwd=repo,
        env=env,
        log_path=compile_log,
    )
    vmiz = repo / "zig-out" / "bin" / "vmiz"
    regular_file(vmiz, "vmiz validator")
    write_json(session / "inputs.json", inputs)
    write_json(
        session / "cache-inventory.json",
        {key: value for key, value in cache_inventory.items() if not key.startswith("_")},
    )
    write_json(session / "package-lock-set.json", lock_set)
    write_json(session / "host.json", host)
    return inputs, cache_inventory, lock_set, env, source_commit, host


def run_acceptance(
    command: Path | None,
    *,
    image: Path,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> dict[str, object]:
    if command is None:
        return {
            "status": "not-available",
            "reason": "repository-has-no-baremetal-boot-acceptance-harness",
        }
    acceptance_env = env.copy()
    acceptance_env["VMIZ_UBUNTU2604_IMAGE"] = str(image)
    acceptance_env["VMIZ_UBUNTU2604_ARCHITECTURE"] = ARCHITECTURE
    acceptance_env["VMIZ_UBUNTU2604_FLAVOR"] = FLAVOR
    run_logged(
        [str(command)],
        cwd=cwd,
        env=acceptance_env,
        log_path=log_path,
    )
    return {"status": "success", "command": str(command)}


def benchmark_command(
    args: argparse.Namespace,
    *,
    work_dir: Path,
    provenance_dir: Path,
    image: Path,
    timing: Path,
) -> list[str]:
    raw_output = image.parent / RAW_ASSET_NAME
    command = [
        str(args.zig),
        "build",
        "-Doptimize=ReleaseSafe",
        "-Dubuntu2604-arch=aarch64",
        "-Dubuntu2604-flavor=baremetal",
        "generalized-ubuntu2604",
        "--",
        "--work-dir",
        str(work_dir),
        "--provenance-dir",
        str(provenance_dir),
        "--output",
        str(image),
        "--raw-output",
        str(raw_output),
        "--source",
        str(args.source.resolve()),
        "--size",
        str(VIRTUAL_SIZE),
        "--authorized-key",
        str(args.authorized_key.resolve()),
        "--uki-stub",
        str(args.uki_stub.resolve()),
        "--uki-signing-certificate",
        str(args.signing_certificate.resolve()),
        "--uki-signing-certificate-sha256",
        args.signing_certificate_sha256,
        "--debz-cache",
        str(args.debz_cache.resolve()),
        "--debz-input-dir",
        str(args.debz_input_dir.resolve()),
        "--debz-lock-dir",
        str(args.debz_lock_dir.resolve()),
        "--timing-output",
        str(timing),
        "--offline",
    ]
    if args.signing_key is not None:
        command.extend(["--uki-signing-key", str(args.signing_key.resolve())])
    else:
        command.extend(["--uki-sign-command", str(args.sign_command.resolve())])
        if args.sign_command_arg is not None:
            command.extend(["--uki-sign-command-arg", args.sign_command_arg])
    return command


def run_once(
    args: argparse.Namespace,
    *,
    repo: Path,
    session: Path,
    env: dict[str, str],
    cache_inventory: dict[str, object],
    lock_set: dict[str, object],
    name: str,
    kind: str,
    reference: dict[str, object] | None,
) -> tuple[dict[str, object], dict[str, object]]:
    run_dir = session / name
    run_dir.mkdir()
    work_dir = run_dir / "work"
    artifact_dir = run_dir / "artifact"
    evidence_dir = run_dir / "evidence"
    provenance_dir = evidence_dir / "provenance"
    work_dir.mkdir()
    artifact_dir.mkdir()
    evidence_dir.mkdir()
    provenance_dir.mkdir()
    shutil.copyfile(args.sha256sums, work_dir / "SHA256SUMS")
    shutil.copyfile(args.sha256sums_signature, work_dir / "SHA256SUMS.gpg")
    shutil.copyfile(args.manifest, work_dir / MANIFEST_NAME)
    image = artifact_dir / ASSET_NAME
    raw_output = artifact_dir / RAW_ASSET_NAME
    timing_path = evidence_dir / "timing.json"
    resources_path = evidence_dir / "resources.json"
    build_log = evidence_dir / "build.log"
    resources = run_measured_command(
        benchmark_command(
            args,
            work_dir=work_dir,
            provenance_dir=provenance_dir,
            image=image,
            timing=timing_path,
        ),
        cwd=repo,
        env=env,
        log_path=build_log,
    )
    write_json(resources_path, resources)
    if resources["status"] != "success":
        fail(f"{name} build failed; benchmark is invalid")
    cache_after = verify_benchmark_cache(
        args.debz_cache, args.debz_input_dir
    )
    # Cache-only refresh may republish validated manifests with a new
    # verified-at timestamp; the content-addressed objects must not change.
    if (
        cache_after["object_inventory_sha256"]
        != cache_inventory["object_inventory_sha256"]
    ):
        fail(f"{name} changed the verified content-addressed cache objects")
    timing = load_timing(timing_path)
    if not image.is_file() or image.stat().st_size <= 0:
        fail(f"{name} did not produce the expected image")
    validate_raw_file(raw_output)
    vmiz = repo / "zig-out" / "bin" / "vmiz"
    check_log = evidence_dir / "vmiz-check.log"
    run_logged(
        [str(vmiz), "check", str(image)],
        cwd=repo,
        env=env,
        log_path=check_log,
    )
    image_info_path = evidence_dir / "image-info.json"
    with image_info_path.open("wb") as output:
        result = subprocess.run(
            [str(vmiz), "info", "--output=json", str(image)],
            cwd=repo,
            env=env,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        fail(f"{name} vmiz info failed: {result.stderr.decode(errors='replace')}")
    image_contract = validate_image_info(image_info_path)
    raw_check_log = evidence_dir / "raw-vmiz-check.log"
    run_logged(
        [str(vmiz), "check", str(raw_output)],
        cwd=repo,
        env=env,
        log_path=raw_check_log,
    )
    raw_info_path = evidence_dir / "raw-image-info.json"
    with raw_info_path.open("wb") as output:
        result = subprocess.run(
            [str(vmiz), "info", "--output=json", str(raw_output)],
            cwd=repo,
            env=env,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        fail(f"{name} raw vmiz info failed: {result.stderr.decode(errors='replace')}")
    raw_output_record = validate_raw_output(raw_output, raw_info_path)
    raw_output_record["retention_policy"] = (
        "keep" if args.keep_images else "delete-after-validation"
    )
    provenance_contract, transaction_provenance_files = validate_provenance(
        provenance_dir,
        lock_set,
        certificate_sha256=args.signing_certificate_sha256,
    )
    acceptance = run_acceptance(
        args.acceptance_command,
        image=image,
        cwd=repo,
        env=env,
        log_path=evidence_dir / "acceptance.log",
    )
    correctness = {
        "profile": {
            "architecture": ARCHITECTURE,
            "flavor": FLAVOR,
            "optimization": OPTIMIZE,
            "source_sha256": SOURCE_SHA256,
        },
        "image": image_contract,
        "raw_output": {
            "format": raw_output_record["format"],
            "virtual_size": raw_output_record["virtual_size"],
            "structural_validation": raw_output_record["structural_validation"],
        },
        "provenance": provenance_contract,
        "package_closure_sha256": lock_set["closure_sha256"],
        "acceptance": acceptance,
    }
    if reference is not None:
        compare_correctness(reference, correctness)
    write_json(evidence_dir / "package-closure.json", lock_set["final_closure"])
    write_json(evidence_dir / "correctness.json", correctness)
    image_digest = sha256(image)
    image_size = image.stat().st_size
    evidence_manifest = {
        "schema": SCHEMA,
        "type": "vmiz-ubuntu2604-image-benchmark-run",
        "name": name,
        "kind": kind,
        "command": benchmark_command(
            args,
            work_dir=work_dir,
            provenance_dir=provenance_dir,
            image=image,
            timing=timing_path,
        ),
        "image": {
            "filename": ASSET_NAME,
            "bytes": image_size,
            "sha256": image_digest,
            "byte_reproducibility_compared": False,
        },
        "raw_output": raw_output_record,
        "transaction_provenance_files": transaction_provenance_files,
        "correctness_sha256": canonical_digest(correctness),
        "cache_inventory_sha256": cache_inventory["inventory_sha256"],
    }
    write_json(evidence_dir / "run-manifest.json", evidence_manifest)
    removed = cleanup_run(
        run_dir,
        image,
        raw_output,
        work_dir,
        keep_images=args.keep_images,
    )
    record = {
        "name": name,
        "kind": kind,
        "timing_values": timing["values"],
        "resources": resources,
        "correctness_sha256": evidence_manifest["correctness_sha256"],
        "image_sha256": image_digest,
        "image_bytes": image_size,
        "raw_output": raw_output_record,
        "evidence": evidence_dir.relative_to(session).as_posix(),
        "cleanup": removed,
    }
    return record, correctness


def run_benchmark(args: argparse.Namespace) -> Path:
    repo = Path(__file__).resolve().parents[1]
    session = prepare_session_dir(args.output_root)
    status_path = session / "benchmark-status.json"
    try:
        _, cache_inventory, lock_set, env, source_commit, host = preflight(
            args, repo, session
        )
        runs = []
        reference = None
        sequence = [("run-warmup", "warmup")] + [
            (f"run-measured-{index:02d}", "measured")
            for index in range(1, MEASURED_RUNS + 1)
        ]
        for name, kind in sequence:
            record, correctness = run_once(
                args,
                repo=repo,
                session=session,
                env=env,
                cache_inventory=cache_inventory,
                lock_set=lock_set,
                name=name,
                kind=kind,
                reference=reference,
            )
            if reference is None:
                reference = correctness
            runs.append(record)
        summary = build_summary(
            runs,
            source_commit=source_commit,
            host=host,
            cache_inventory=cache_inventory,
            lock_set=lock_set,
        )
        write_json(session / "benchmark-summary.json", summary)
        (session / "benchmark-summary.txt").write_text(
            readable_summary(summary), encoding="utf-8"
        )
        write_json(
            status_path,
            {
                "schema": SCHEMA,
                "type": "vmiz-ubuntu2604-image-benchmark-status",
                "status": "valid",
            },
        )
        return session
    except Exception as raw_error:
        error = (
            raw_error
            if isinstance(raw_error, BenchmarkError)
            else BenchmarkError(f"{type(raw_error).__name__}: {raw_error}")
        )
        write_json(
            status_path,
            {
                "schema": SCHEMA,
                "type": "vmiz-ubuntu2604-image-benchmark-status",
                "status": "invalid",
                "error": str(error),
            },
        )
        raise error


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        session = run_benchmark(args)
    except BenchmarkError as error:
        print(f"benchmark invalid: {error}", file=sys.stderr)
        return 1
    print(f"benchmark complete: {session / 'benchmark-summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
