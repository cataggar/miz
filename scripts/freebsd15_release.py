#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


# One entry per architecture x root filesystem x flavor the FreeBSD builder
# can produce. These values duplicate the Zig builder's profile table on
# purpose: the release workflow must be able to reject a candidate without
# trusting the builder that produced it. tests/freebsd15_release_test.py keeps
# the two tables in agreement.
VARIANTS = {
    "aarch64-ufs-full": {
        "architecture": "aarch64",
        "filesystem": "ufs",
        "flavor": "full",
        "source_directory": "aarch64",
        "asset_name": "FreeBSD-15.1-aarch64.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-arm64-aarch64-"
            "BASIC-CLOUDINIT-ufs.qcow2.xz"
        ),
        "source_sha256": (
            "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963"
        ),
        "virtual_size": 6_477_643_776,
        "runner": "ubuntu-24.04-arm",
        "qemu": "/usr/bin/qemu-system-aarch64",
    },
    "x86_64-ufs-full": {
        "architecture": "x86_64",
        "filesystem": "ufs",
        "flavor": "full",
        "source_directory": "amd64",
        "asset_name": "FreeBSD-15.1-x86_64.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
        ),
        "source_sha256": (
            "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f"
        ),
        "virtual_size": 6_477_709_312,
        "runner": "ubuntu-24.04",
        "qemu": "/usr/bin/qemu-system-x86_64",
    },
    "aarch64-zfs-full": {
        "architecture": "aarch64",
        "filesystem": "zfs",
        "flavor": "full",
        "source_directory": "aarch64",
        "asset_name": "FreeBSD-15.1-aarch64.zfs.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-arm64-aarch64-"
            "BASIC-CLOUDINIT-zfs.qcow2.xz"
        ),
        "source_sha256": (
            "0911a033b0a5d060486f92e534f3482c6a2ab96af6abb8a60683eeb24f6746af"
        ),
        "virtual_size": 6_477_643_776,
        "runner": "ubuntu-24.04-arm",
        "qemu": "/usr/bin/qemu-system-aarch64",
    },
    "x86_64-zfs-full": {
        "architecture": "x86_64",
        "filesystem": "zfs",
        "flavor": "full",
        "source_directory": "amd64",
        "asset_name": "FreeBSD-15.1-x86_64.zfs.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz"
        ),
        "source_sha256": (
            "4159e137d4a78f46b62d3523edd9a4dc79fd0cdcf17e34e531342f52333f4131"
        ),
        "virtual_size": 6_477_840_384,
        "runner": "ubuntu-24.04",
        "qemu": "/usr/bin/qemu-system-x86_64",
    },
    # The core variants start from the same pinned UFS sources as the full
    # ones: only the package manifest the guest realizes differs.
    "aarch64-ufs-core": {
        "architecture": "aarch64",
        "filesystem": "ufs",
        "flavor": "core",
        "source_directory": "aarch64",
        "asset_name": "FreeBSD-15.1-aarch64.core.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-arm64-aarch64-"
            "BASIC-CLOUDINIT-ufs.qcow2.xz"
        ),
        "source_sha256": (
            "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963"
        ),
        "virtual_size": 6_477_643_776,
        "runner": "ubuntu-24.04-arm",
        "qemu": "/usr/bin/qemu-system-aarch64",
    },
    "x86_64-ufs-core": {
        "architecture": "x86_64",
        "filesystem": "ufs",
        "flavor": "core",
        "source_directory": "amd64",
        "asset_name": "FreeBSD-15.1-x86_64.core.qcow2",
        "source_name": (
            "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
        ),
        "source_sha256": (
            "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f"
        ),
        "virtual_size": 6_477_709_312,
        "runner": "ubuntu-24.04",
        "qemu": "/usr/bin/qemu-system-x86_64",
    },
}

# The retained contract and the reviewed exclusions, mirrored from
# scripts/freebsd15_package_manifest.zig. The duplication is the point: the
# release helper validates the manifest an image actually recorded without
# trusting the builder that produced it, exactly as it does for the profile
# table. tests/freebsd15_release_test.py keeps the two in agreement.
REQUIRED_PACKAGES = (
    "FreeBSD-set-minimal",
    "FreeBSD-runtime",
    "FreeBSD-rc",
    "FreeBSD-pam",
    "FreeBSD-bootloader",
    "FreeBSD-efi-tools",
    "FreeBSD-kernel-generic",
    "FreeBSD-hyperv-tools",
    "FreeBSD-devd",
    "FreeBSD-dhclient",
    "FreeBSD-resolvconf",
    "FreeBSD-caroot",
    "FreeBSD-certctl",
    "FreeBSD-openssl",
    "FreeBSD-ntp",
    "FreeBSD-ssh",
    "FreeBSD-rescue",
    "FreeBSD-utilities",
    "FreeBSD-vi",
    "FreeBSD-geom",
    "FreeBSD-ufs",
    "FreeBSD-nuageinit",
    "FreeBSD-flua",
    "FreeBSD-pkg-bootstrap",
    "FreeBSD-libarchive",
    "pkg",
    "azure-agent",
)

LIBRARY_ROOTS = (
    "FreeBSD-audit-lib",
    "FreeBSD-blocklist",
    "FreeBSD-ctf-lib",
    "FreeBSD-kerberos-lib",
    "FreeBSD-libbsdstat",
    "FreeBSD-libcasper",
    "FreeBSD-libldns",
    "FreeBSD-libmagic",
    "FreeBSD-libucl",
    "FreeBSD-libyaml",
    "FreeBSD-natd",
    "FreeBSD-openssl-lib",
    "FreeBSD-tcpd",
)

CORE_EXCLUDED_PACKAGES = (
    "FreeBSD-clang",
    "FreeBSD-lld",
    "FreeBSD-lldb",
    "FreeBSD-toolchain",
    "FreeBSD-bmake",
    "FreeBSD-ctf",
    "FreeBSD-dtrace",
    "FreeBSD-dwatch",
    "FreeBSD-tests",
    "FreeBSD-atf",
    "FreeBSD-kyua",
    "FreeBSD-src",
    "FreeBSD-src-sys",
    "FreeBSD-examples",
    "FreeBSD-games",
    "FreeBSD-bhyve",
    "FreeBSD-bluetooth",
    "FreeBSD-hostapd",
    "FreeBSD-sound",
    "FreeBSD-cxgbe-tools",
    "FreeBSD-mlx-tools",
    "FreeBSD-kerberos",
    "FreeBSD-kerberos-kdc",
    "FreeBSD-sendmail",
    "FreeBSD-set-base",
    "FreeBSD-set-devel",
    "FreeBSD-set-optional",
    "FreeBSD-set-src",
    "FreeBSD-set-tests",
    "FreeBSD-set-lib32",
)

CORE_EXCLUDED_CLASSES = ("dbg", "dev", "lib32")

PACKAGE_MANIFEST_REVISION = 1

PACKAGE_MANIFESTS = {
    "full": {
        "revision": PACKAGE_MANIFEST_REVISION,
        "required": REQUIRED_PACKAGES,
        "library_roots": (),
        "excluded": (),
        "excluded_classes": (),
        "prunes": False,
    },
    "core": {
        "revision": PACKAGE_MANIFEST_REVISION,
        "required": REQUIRED_PACKAGES,
        "library_roots": LIBRARY_ROOTS,
        "excluded": CORE_EXCLUDED_PACKAGES,
        "excluded_classes": CORE_EXCLUDED_CLASSES,
        "prunes": True,
    },
}

SOURCE_URL_PREFIX = (
    "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/"
)

# A release set is exactly the assets one dispatch of the release workflow is
# allowed to publish. Keeping the tag, title, and asset allowlist together is
# what lets the publisher refuse an incomplete or unexpected upload without
# consulting a second source of truth.
RELEASE_SETS = {
    "ufs": {
        "release_tag": "FreeBSD-15.1-20260724",
        "release_title": "FreeBSD 15.1 - 20260724",
        "variants": ("aarch64-ufs-full", "x86_64-ufs-full"),
        "summary": (
            "Generalized FreeBSD 15.1-RELEASE UFS images built with zvmi."
        ),
        "highlights": (
            "Added matching AArch64 and x86_64 release images.",
            "Each asset is a standalone zstd-compressed QCOW2 with no backing "
            "file.",
            "First boot grows the UFS root partition and filesystem to fill a "
            "larger disk without disturbing GPT metadata.",
        ),
    },
    "zfs": {
        "release_tag": "FreeBSD-15.1-zfs-20260729",
        "release_title": "FreeBSD 15.1 ZFS - 20260729",
        "variants": ("aarch64-zfs-full", "x86_64-zfs-full"),
        "summary": (
            "Generalized FreeBSD 15.1-RELEASE ZFS-root images built with zvmi."
        ),
        "highlights": (
            "Added matching AArch64 and x86_64 ZFS-root release images.",
            "Each asset is a standalone zstd-compressed QCOW2 with no backing "
            "file.",
            "First boot grows the last GPT partition and onlines the enlarged "
            "`zroot` vdev; `autoexpand` keeps later enlargements working.",
            "`zpool_reguid` gives every instance a distinct pool GUID.",
        ),
    },
    "core": {
        "release_tag": "FreeBSD-15.1-core-20260730",
        "release_title": "FreeBSD 15.1 Core - 20260730",
        "variants": ("aarch64-ufs-core", "x86_64-ufs-core"),
        "summary": (
            "Generalized FreeBSD 15.1-RELEASE UFS core images built with "
            "zvmi."
        ),
        "highlights": (
            "Added matching AArch64 and x86_64 core release images.",
            "The core flavor is realized by pkg from an explicit, reviewed "
            "pkgbase manifest, not by deleting files from a full image.",
            "Compilers, debuggers, development headers, debug symbols, "
            "32-bit compatibility libraries, tests, sources, and hardware "
            "support the supported virtual machines never use are excluded.",
            "UEFI boot, the release kernel, virtio and Hyper-V support, "
            "key-only OpenSSH, nuageinit provisioning, `pkg`, the "
            "FreeBSD-base update path, and the Azure Agent are retained and "
            "verified in the guest and again on the host.",
            "Package caches are removed and unused filesystem space is "
            "reclaimed before the final standalone zstd QCOW2 compression.",
        ),
    },
}

AZURE_CONTRACTS = (
    "matching-architecture-gen2",
    "key-only-ssh",
    "agent-ready",
    "hn0-dhcp",
    "serial-console",
    "zfs-root",
    "zpool-healthy",
    "root-growth",
    "gpt-healthy",
    "reboot-reconnect",
    "instance-identity",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CANDIDATE_SCHEMA = 3
# Core publication requires at least this reduction in both qemu-img's
# allocated size and the downloadable compressed file size. Ten percent is a
# conservative default: large enough to reject noise from QCOW2 metadata and
# compression variance, while leaving the reviewed package manifest—not an
# aggressive size target—as the primary definition of "core".
CORE_MINIMUM_REDUCTION_PERCENT = 10
PROFILE_KEYS = (
    "architecture",
    "filesystem",
    "flavor",
    "asset_name",
)
PACKAGE_RECORD_RE = re.compile(r"^(\S+) (\S+) (\d+)$")


def variant_key(architecture: str, filesystem: str, flavor: str) -> str:
    key = f"{architecture}-{filesystem}-{flavor}"
    if key not in VARIANTS:
        raise ValueError(f"unsupported FreeBSD variant: {key}")
    return key


def package_manifest(flavor: str) -> dict:
    if flavor not in PACKAGE_MANIFESTS:
        raise ValueError(f"unsupported FreeBSD flavor: {flavor}")
    return PACKAGE_MANIFESTS[flavor]


def has_name_class(name: str, name_class: str) -> bool:
    # FreeBSD names every member of these families with the class as the final
    # hyphen-separated component, so an exact component match avoids mistaking
    # FreeBSD-devd or FreeBSD-devmatch for a development package.
    return name.startswith("FreeBSD-") and name.endswith(f"-{name_class}")


def parse_package_manifest(path: Path) -> list[dict]:
    """Parse a `<asset>.packages.txt` the builder recorded from the guest."""
    packages = []
    seen = set()
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = PACKAGE_RECORD_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"{path}:{number}: malformed package record")
        name, version, installed_bytes = match.groups()
        if name in seen:
            raise ValueError(f"{path}:{number}: duplicate package {name}")
        seen.add(name)
        packages.append(
            {
                "name": name,
                "version": version,
                "installed_bytes": int(installed_bytes),
            }
        )
    if not packages:
        raise ValueError(f"{path}: no packages recorded")
    return packages


def verify_package_manifest(flavor: str, packages: list[dict]) -> None:
    """Check a recorded manifest against the reviewed one for `flavor`.

    The builder already did this, but the release helper must be able to
    reject a candidate without trusting the builder that produced it.
    """
    manifest = package_manifest(flavor)
    installed = {package["name"] for package in packages}
    for required in manifest["required"]:
        if required not in installed:
            raise ValueError(f"recorded manifest is missing {required}")
    for name in sorted(installed):
        if name in manifest["excluded"]:
            raise ValueError(f"recorded manifest still carries {name}")
        for name_class in manifest["excluded_classes"]:
            if has_name_class(name, name_class):
                raise ValueError(f"recorded manifest still carries {name}")


def release_set(name: str) -> dict:
    if name not in RELEASE_SETS:
        raise ValueError(f"unsupported FreeBSD release set: {name}")
    return RELEASE_SETS[name]


def source_url(key: str) -> str:
    variant = VARIANTS[key]
    return (
        f"{SOURCE_URL_PREFIX}{variant['source_directory']}/Latest/"
        f"{variant['source_name']}"
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha256(value: str, label: str) -> None:
    if not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def require_non_empty(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")
    return value.strip()


def require_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def require_reduction_percent(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 99:
        raise ValueError("minimum core reduction percent must be from 1 to 99")
    return value


def load_qemu_image_info(path: Path, expected_virtual_size: int) -> dict:
    """Load the trusted qemu-img validation result used for size metadata."""
    document = json.loads(path.resolve(strict=True).read_text(encoding="utf-8"))
    if document.get("format") != "qcow2":
        raise ValueError("qemu-img validation format must be qcow2")
    virtual_size = require_positive_int(
        document.get("virtual-size"),
        "qemu-img virtual size",
    )
    if virtual_size != expected_virtual_size:
        raise ValueError("qemu-img virtual size does not match the pinned profile")
    allocated_size = require_positive_int(
        document.get("actual-size"),
        "qemu-img allocated size",
    )
    if allocated_size > virtual_size:
        raise ValueError("qemu-img allocated size exceeds virtual size")
    if document.get("backing-filename") not in (None, ""):
        raise ValueError("qemu-img validation reports a backing file")
    compression_type = (
        document.get("format-specific", {})
        .get("data", {})
        .get("compression-type")
    )
    if compression_type != "zstd":
        raise ValueError("qemu-img validation compression type must be zstd")
    return {
        "format": "qcow2",
        "virtual_size": virtual_size,
        "allocated_size": allocated_size,
        "compression_type": compression_type,
        "has_backing_file": False,
    }


def matrix_command(args: argparse.Namespace) -> None:
    selected = release_set(args.release_set)
    include = []
    for key in selected["variants"]:
        variant = VARIANTS[key]
        include.append(
            {
                "variant": key,
                "architecture": variant["architecture"],
                "filesystem": variant["filesystem"],
                "flavor": variant["flavor"],
                "asset_name": variant["asset_name"],
                "source_name": variant["source_name"],
                "source_url": source_url(key),
                "source_sha256": variant["source_sha256"],
                "virtual_size": variant["virtual_size"],
                "runner": variant["runner"],
                "qemu": variant["qemu"],
            }
        )
    print(json.dumps({"include": include}, sort_keys=True))


def describe_command(args: argparse.Namespace) -> None:
    selected = release_set(args.release_set)
    print(f"release_tag={selected['release_tag']}")
    print(f"release_title={selected['release_title']}")
    print(f"asset_count={len(selected['variants'])}")


def candidate_command(args: argparse.Namespace) -> None:
    key = variant_key(args.architecture, args.filesystem, args.flavor)
    expected = VARIANTS[key]
    asset = args.asset.resolve(strict=True)
    if asset.name != expected["asset_name"]:
        raise ValueError(f"{key} asset must be {expected['asset_name']}")
    require_sha256(args.validated_sha256, "validated SHA-256")
    actual_sha256 = sha256(asset)
    if actual_sha256 != args.validated_sha256:
        raise ValueError("validated SHA-256 does not match the candidate")
    if args.virtual_size != expected["virtual_size"]:
        raise ValueError("candidate virtual size does not match the pinned profile")
    qemu_image = load_qemu_image_info(args.qemu_info, args.virtual_size)
    if args.source_name != expected["source_name"]:
        raise ValueError("source filename does not match the pinned profile")
    if args.source_sha256 != expected["source_sha256"]:
        raise ValueError("source SHA-256 does not match the pinned profile")
    require_sha256(args.source_sha256, "source SHA-256")
    if args.source_bytes <= 0:
        raise ValueError("source size must be positive")
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise ValueError("source commit must be a lowercase 40-character SHA")
    if args.source_url != source_url(key):
        raise ValueError("source URL does not match the pinned profile")
    if not args.qemu_version.strip() or not args.runner.strip():
        raise ValueError("QEMU version and runner must be recorded")
    packages = parse_package_manifest(args.package_manifest.resolve(strict=True))
    verify_package_manifest(expected["flavor"], packages)

    document = {
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-candidate",
        "variant": key,
        "architecture": expected["architecture"],
        "filesystem": expected["filesystem"],
        "flavor": expected["flavor"],
        "asset_name": asset.name,
        "compressed_size": asset.stat().st_size,
        "allocated_size": qemu_image["allocated_size"],
        "asset_sha256": actual_sha256,
        "virtual_size": args.virtual_size,
        "packages": {
            "manifest_revision": package_manifest(expected["flavor"])["revision"],
            "count": len(packages),
            "installed_bytes": sum(
                package["installed_bytes"] for package in packages
            ),
            "names": [package["name"] for package in packages],
        },
        "source": {
            "name": args.source_name,
            "url": args.source_url,
            "bytes": args.source_bytes,
            "sha256": args.source_sha256,
        },
        "source_commit": args.source_commit,
        "validation": {
            "qemu_version": args.qemu_version.strip(),
            "qemu_image": qemu_image,
            "runner": args.runner.strip(),
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def azure_result_command(args: argparse.Namespace) -> None:
    manifest_path = args.manifest.resolve(strict=True)
    candidate, asset_path = validate_candidate(manifest_path, args.source_commit)
    if candidate["variant"] != args.key:
        raise ValueError("candidate variant does not match --key")
    if candidate["filesystem"] != "zfs":
        raise ValueError("azure-result requires a zfs candidate")
    # Independently verify the asset the caller points to is the same file the
    # candidate manifest describes — the harness may pass a path that differs
    # from the one validate_candidate resolved (same file, different argument).
    asset = args.asset.resolve(strict=True)
    if asset != asset_path.resolve():
        actual_asset_sha256 = sha256(asset)
        if actual_asset_sha256 != candidate["asset_sha256"]:
            raise ValueError("--asset does not match the candidate digest")
    require_sha256(args.vhd_sha256, "VHD SHA-256")
    if args.vhd_bytes <= 0:
        raise ValueError("VHD size must be positive")
    # Validate contracts passed as a comma-separated string.
    provided_contracts = [c.strip() for c in args.contracts.split(",")]
    if provided_contracts != list(AZURE_CONTRACTS):
        raise ValueError(
            "contracts do not match required Azure contracts"
        )
    location = require_non_empty(args.location, "location")
    vm_size = require_non_empty(args.vm_size, "vm_size")
    resource_group = require_non_empty(args.resource_group, "resource_group")
    workflow_run_id = require_non_empty(str(args.run_id), "run_id")
    workflow_run_attempt = require_non_empty(
        str(args.run_attempt),
        "run_attempt",
    )

    document = {
        "schema": 1,
        "type": "zvmi-freebsd15-azure-acceptance",
        "variant": candidate["variant"],
        "architecture": candidate["architecture"],
        "filesystem": candidate["filesystem"],
        "flavor": candidate["flavor"],
        "asset_name": candidate["asset_name"],
        "source_commit": args.source_commit,
        "qcow_sha256": candidate["asset_sha256"],
        "derived_vhd_sha256": args.vhd_sha256,
        "derived_vhd_bytes": args.vhd_bytes,
        "status": "success",
        "location": location,
        "vm_size": vm_size,
        "resource_group": resource_group,
        "contracts": list(AZURE_CONTRACTS),
        "workflow": {
            "run_id": workflow_run_id,
            "run_attempt": workflow_run_attempt,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_candidate(
    manifest_path: Path,
    source_commit: str,
) -> tuple[dict, Path]:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema") != CANDIDATE_SCHEMA:
        raise ValueError(f"{manifest_path}: unsupported schema")
    if document.get("type") != "zvmi-freebsd15-candidate":
        raise ValueError(f"{manifest_path}: unexpected candidate type")
    key = document.get("variant")
    if key not in VARIANTS:
        raise ValueError(f"{manifest_path}: unexpected variant")
    expected = VARIANTS[key]
    for profile_key in PROFILE_KEYS:
        if document.get(profile_key) != expected[profile_key]:
            raise ValueError(
                f"{manifest_path}: {profile_key} does not match profile"
            )
    if document.get("virtual_size") != expected["virtual_size"]:
        raise ValueError(f"{manifest_path}: virtual_size does not match profile")
    compressed_size = require_positive_int(
        document.get("compressed_size"),
        f"{manifest_path}: compressed size",
    )
    allocated_size = require_positive_int(
        document.get("allocated_size"),
        f"{manifest_path}: allocated size",
    )
    if allocated_size > document["virtual_size"]:
        raise ValueError(f"{manifest_path}: allocated size exceeds virtual size")
    validation = document.get("validation")
    if not isinstance(validation, dict):
        raise ValueError(f"{manifest_path}: validation metadata is missing")
    qemu_image = validation.get("qemu_image")
    if not isinstance(qemu_image, dict):
        raise ValueError(f"{manifest_path}: qemu-img validation metadata is missing")
    expected_qemu_image = {
        "format": "qcow2",
        "virtual_size": document["virtual_size"],
        "allocated_size": allocated_size,
        "compression_type": "zstd",
        "has_backing_file": False,
    }
    if qemu_image != expected_qemu_image:
        raise ValueError(f"{manifest_path}: qemu-img size metadata mismatch")
    for source_key in ("name", "sha256"):
        if document["source"][source_key] != expected[f"source_{source_key}"]:
            raise ValueError(
                f"{manifest_path}: source {source_key} does not match profile"
            )
    if document["source"]["url"] != source_url(key):
        raise ValueError(f"{manifest_path}: source url does not match profile")
    if document.get("source_commit") != source_commit:
        raise ValueError(f"{manifest_path}: source commit mismatch")
    asset = manifest_path.parent / document["asset_name"]
    if not asset.is_file():
        raise ValueError(f"{manifest_path}: candidate asset is missing")
    if asset.stat().st_size != compressed_size:
        raise ValueError(f"{manifest_path}: candidate size mismatch")
    if sha256(asset) != document.get("asset_sha256"):
        raise ValueError(f"{manifest_path}: candidate digest mismatch")
    require_sha256(document["asset_sha256"], "candidate SHA-256")
    require_sha256(document["source"]["sha256"], "source SHA-256")
    recorded = document.get("packages")
    if not isinstance(recorded, dict) or not recorded.get("names"):
        raise ValueError(f"{manifest_path}: no recorded package manifest")
    reviewed = package_manifest(expected["flavor"])
    if recorded.get("manifest_revision") != reviewed["revision"]:
        raise ValueError(
            f"{manifest_path}: package manifest revision does not match"
        )
    if recorded.get("count") != len(recorded["names"]):
        raise ValueError(f"{manifest_path}: package count does not match")
    verify_package_manifest(
        expected["flavor"],
        [{"name": name} for name in recorded["names"]],
    )
    return document, asset


def release_notes(
    selected: dict,
    candidates: list[dict],
    source_commit: str,
    azure_results: dict[str, dict] | None = None,
    minimum_core_reduction_percent: int | None = None,
) -> str:
    lines = [selected["summary"], "", "## Highlights", ""]
    lines.extend(f"- {highlight}" for highlight in selected["highlights"])
    lines.extend(
        [
            "- Both architectures passed dual-instance UEFI QEMU acceptance "
            "with NoCloud provisioning, key-only SSH, reboot, and identity "
            "separation.",
            "- Images include Azure Agent, generic and Hyper-V DHCP "
            "configuration, and FreeBSD's Azure serial-console settings.",
            "",
            "## Assets",
            "",
            "| Architecture | Root | Flavor | Asset | Virtual size | "
            "Allocated size | Compressed/download size | SHA-256 |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for candidate in candidates:
        lines.append(
            "| {architecture} | {filesystem} | {flavor} | `{asset_name}` "
            "| {virtual_size} | {allocated_size} | {compressed_size} "
            "| `{asset_sha256}` |".format(
                **candidate
            )
        )
    if minimum_core_reduction_percent is not None:
        lines.extend(
            [
                "",
                "## Core size gate",
                "",
                f"Both architectures reduced qemu-img allocated size and "
                f"compressed/download size by at least "
                f"{minimum_core_reduction_percent}% versus the corresponding "
                "full UFS release assets. Virtual size is reported above and "
                "may not regress.",
            ]
        )
    lines.extend(
        [
            "",
            "## Installed packages",
            "",
            "| Asset | Manifest revision | Packages | Installed bytes |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for candidate in candidates:
        packages = candidate["packages"]
        lines.append(
            "| `{asset}` | {revision} | {count} | {installed} |".format(
                asset=candidate["asset_name"],
                revision=packages["manifest_revision"],
                count=packages["count"],
                installed=packages["installed_bytes"],
            )
        )
    for candidate in candidates:
        lines.extend(
            [
                "",
                f"<details><summary>{candidate['asset_name']} package "
                "manifest</summary>",
                "",
                "```",
                *candidate["packages"]["names"],
                "```",
                "",
                "</details>",
            ]
        )
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Source commit: `{source_commit}`",
        ]
    )
    for candidate in candidates:
        source = candidate["source"]
        validation = candidate["validation"]
        lines.extend(
            [
                f"- {candidate['variant']} source: `{source['name']}`",
                f"  - URL: {source['url']}",
                f"  - File size: {source['bytes']} bytes",
                f"  - SHA-256: `{source['sha256']}`",
                f"  - QEMU acceptance: `{validation['qemu_version']}` on "
                f"`{validation['runner']}`",
            ]
        )
    if azure_results is not None:
        lines.extend(
            [
                "",
                "## Azure validation",
                "",
                "- Exact-candidate matching-architecture Gen2 validation is "
                "complete for every ZFS release asset.",
            ]
        )
        for candidate in candidates:
            azure = azure_results[candidate["variant"]]
            lines.extend(
                [
                    f"- {candidate['variant']}: `{azure['location']}` / "
                    f"`{azure['vm_size']}`",
                    f"  - Derived VHD SHA-256: "
                    f"`{azure['derived_vhd_sha256']}`",
                    f"  - Derived VHD size: "
                    f"{azure['derived_vhd_bytes']} bytes",
                ]
            )
        lines.extend(
            [
                "",
                "The QCOW2 assets are not directly uploadable to Azure. "
                "Validation was completed on aligned fixed VHDs derived with "
                "`zvmi azure derive` from these exact release candidates.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "The QCOW2 assets are not directly uploadable to Azure. "
                "Derive an aligned fixed VHD with `zvmi azure derive` before "
                "upload. The exact release candidates were validated under "
                "UEFI QEMU; this release does not claim exact-candidate Azure "
                "validation.",
            ]
        )
    lines.extend(
        [
            "",
            "No checksum sidecar assets are published.",
            "",
        ]
    )
    return "\n".join(lines)


def stage_command(args: argparse.Namespace) -> None:
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise ValueError("source commit must be a lowercase 40-character SHA")
    selected = release_set(args.release_set)
    if args.release_tag != selected["release_tag"]:
        raise ValueError(
            f"{args.release_set} releases must be tagged "
            f"{selected['release_tag']}"
        )
    if args.release_set == "zfs":
        if args.azure_results is None:
            raise ValueError("zfs releases require --azure-results")
    elif args.azure_results is not None:
        raise ValueError("azure results are not applicable to this release set")

    wanted = selected["variants"]
    manifests = sorted(args.candidates.rglob("candidate.json"))
    if len(manifests) != len(wanted):
        raise ValueError(f"expected {len(wanted)} candidate manifests")

    by_variant = {}
    assets = {}
    for manifest in manifests:
        candidate, asset = validate_candidate(manifest, args.source_commit)
        key = candidate["variant"]
        if key in by_variant:
            raise ValueError(f"duplicate {key} candidate")
        by_variant[key] = candidate
        assets[key] = asset
    if set(by_variant) != set(wanted):
        raise ValueError(
            f"{args.release_set} candidate matrix is incomplete or unexpected"
        )

    minimum_reduction = require_reduction_percent(
        getattr(
            args,
            "minimum_core_reduction_percent",
            CORE_MINIMUM_REDUCTION_PERCENT,
        )
    )
    if args.release_set == "core":
        if getattr(args, "baseline", None) is None:
            raise ValueError("core releases require a full UFS --baseline")
        baseline = load_publish_manifest(args.baseline)
        core_rows = full_core_rows(baseline, {
            "schema": CANDIDATE_SCHEMA,
            "type": "zvmi-freebsd15-release",
            "release_set": "core",
            "release_tag": selected["release_tag"],
            "source_commit": args.source_commit,
            "assets": [
                candidate_release_asset(by_variant[key]) for key in wanted
            ],
        })
        enforce_core_size_gate(core_rows, minimum_reduction)
    elif getattr(args, "baseline", None) is not None:
        raise ValueError("a size baseline is only applicable to core releases")

    azure_by_variant = None
    if args.release_set == "zfs":
        azure_manifests = sorted(args.azure_results.rglob("azure-result.json"))
        if len(azure_manifests) != len(wanted):
            raise ValueError(f"expected {len(wanted)} azure result manifests")
        azure_by_variant = {}
        for azure_manifest in azure_manifests:
            document = json.loads(azure_manifest.read_text(encoding="utf-8"))
            if document.get("schema") != 1:
                raise ValueError(f"{azure_manifest}: unsupported schema")
            if document.get("type") != "zvmi-freebsd15-azure-acceptance":
                raise ValueError(f"{azure_manifest}: unexpected azure result type")
            key = document.get("variant")
            if key not in wanted:
                raise ValueError(f"{azure_manifest}: unexpected variant")
            if key in azure_by_variant:
                raise ValueError(f"duplicate {key} azure result")
            candidate = by_variant[key]
            expected = VARIANTS[key]
            for profile_key in (
                "architecture",
                "filesystem",
                "flavor",
                "asset_name",
            ):
                if document.get(profile_key) != expected[profile_key]:
                    raise ValueError(
                        f"{azure_manifest}: {profile_key} does not match profile"
                    )
            if document.get("filesystem") != "zfs":
                raise ValueError(f"{azure_manifest}: filesystem must be zfs")
            if document.get("flavor") != "full":
                raise ValueError(f"{azure_manifest}: flavor must be full")
            if document.get("source_commit") != args.source_commit:
                raise ValueError(f"{azure_manifest}: source commit mismatch")
            if document.get("qcow_sha256") != candidate["asset_sha256"]:
                raise ValueError(
                    f"{azure_manifest}: QCOW SHA-256 does not match candidate"
                )
            if document.get("status") != "success":
                raise ValueError(f"{azure_manifest}: status is not success")
            derived_vhd_bytes = document.get("derived_vhd_bytes")
            if not isinstance(derived_vhd_bytes, int) or derived_vhd_bytes <= 0:
                raise ValueError(
                    f"{azure_manifest}: derived VHD size must be positive"
                )
            require_sha256(
                document.get("derived_vhd_sha256", ""),
                "derived VHD SHA-256",
            )
            require_non_empty(document.get("location", ""), "location")
            require_non_empty(document.get("vm_size", ""), "vm_size")
            require_non_empty(
                document.get("resource_group", ""),
                "resource_group",
            )
            if document.get("contracts") != list(AZURE_CONTRACTS):
                raise ValueError(
                    f"{azure_manifest}: contracts do not match required Azure contracts"
                )
            workflow = document.get("workflow")
            if not isinstance(workflow, dict):
                raise ValueError(f"{azure_manifest}: workflow is missing")
            require_non_empty(str(workflow.get("run_id", "")), "run_id")
            require_non_empty(
                str(workflow.get("run_attempt", "")),
                "run_attempt",
            )
            azure_by_variant[key] = document
        if set(azure_by_variant) != set(wanted):
            raise ValueError(
                f"{args.release_set} azure result matrix is incomplete or unexpected"
            )

    args.output.mkdir(parents=True, exist_ok=True)
    candidates = [by_variant[key] for key in wanted]
    for candidate in candidates:
        destination = args.output / candidate["asset_name"]
        if destination.exists():
            raise ValueError(f"staged asset already exists: {destination}")
        shutil.copyfile(assets[candidate["variant"]], destination)
        if sha256(destination) != candidate["asset_sha256"]:
            raise ValueError("staged asset digest mismatch")

    manifest_assets = []
    for candidate in candidates:
        asset_manifest = candidate_release_asset(candidate)
        if azure_by_variant is not None:
            azure = azure_by_variant[candidate["variant"]]
            asset_manifest["azure"] = {
                "location": azure["location"],
                "vm_size": azure["vm_size"],
                "derived_vhd_sha256": azure["derived_vhd_sha256"],
                "derived_vhd_bytes": azure["derived_vhd_bytes"],
                "contracts": azure["contracts"],
            }
        manifest_assets.append(asset_manifest)

    manifest = {
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-release",
        "release_set": args.release_set,
        "release_tag": args.release_tag,
        "source_commit": args.source_commit,
        "assets": manifest_assets,
    }
    (args.output / "publish-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.notes.write_text(
        release_notes(
            selected,
            candidates,
            args.source_commit,
            azure_results=azure_by_variant,
            minimum_core_reduction_percent=(
                minimum_reduction if args.release_set == "core" else None
            ),
        ),
        encoding="utf-8",
    )


def candidate_release_asset(candidate: dict) -> dict:
    return {
        "variant": candidate["variant"],
        "architecture": candidate["architecture"],
        "filesystem": candidate["filesystem"],
        "flavor": candidate["flavor"],
        "asset_name": candidate["asset_name"],
        # `bytes` remains the publisher-facing download size field. Schema 3
        # also names it explicitly so comparisons cannot confuse it with the
        # qemu-img allocated size.
        "bytes": candidate["compressed_size"],
        "compressed_size": candidate["compressed_size"],
        "allocated_size": candidate["allocated_size"],
        "virtual_size": candidate["virtual_size"],
        "sha256": candidate["asset_sha256"],
        "packages": candidate["packages"]["count"],
    }


def load_publish_manifest(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("type") != "zvmi-freebsd15-release":
        raise ValueError(f"{path}: not a publish manifest")
    if document.get("schema") != CANDIDATE_SCHEMA:
        raise ValueError(f"{path}: unsupported schema")
    release_set_name = document.get("release_set")
    if release_set_name not in RELEASE_SETS:
        raise ValueError(f"{path}: unexpected release set")
    selected = RELEASE_SETS[release_set_name]
    if document.get("release_tag") != selected["release_tag"]:
        raise ValueError(f"{path}: release tag does not match release set")
    assets = document.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError(f"{path}: release assets are missing")
    by_variant = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError(f"{path}: invalid release asset")
        key = asset.get("variant")
        if key not in VARIANTS or key in by_variant:
            raise ValueError(f"{path}: unexpected or duplicate release variant")
        expected = VARIANTS[key]
        for profile_key in PROFILE_KEYS:
            if asset.get(profile_key) != expected[profile_key]:
                raise ValueError(
                    f"{path}: {key} {profile_key} does not match profile"
                )
        virtual_size = require_positive_int(
            asset.get("virtual_size"),
            f"{path}: {key} virtual size",
        )
        if virtual_size != expected["virtual_size"]:
            raise ValueError(f"{path}: {key} virtual size does not match profile")
        allocated_size = require_positive_int(
            asset.get("allocated_size"),
            f"{path}: {key} allocated size",
        )
        if allocated_size > virtual_size:
            raise ValueError(f"{path}: {key} allocated size exceeds virtual size")
        compressed_size = require_positive_int(
            asset.get("compressed_size"),
            f"{path}: {key} compressed size",
        )
        if asset.get("bytes") != compressed_size:
            raise ValueError(f"{path}: {key} download size does not match")
        require_sha256(asset.get("sha256", ""), f"{path}: {key} SHA-256")
        require_positive_int(asset.get("packages"), f"{path}: {key} package count")
        by_variant[key] = asset
    if set(by_variant) != set(selected["variants"]):
        raise ValueError(f"{path}: release asset matrix is incomplete or unexpected")
    return document


def full_core_rows(baseline: dict, candidate: dict) -> list[tuple[dict, dict]]:
    """Return architecture pairs in the only allowed comparison direction."""
    if baseline.get("release_set") != "ufs":
        raise ValueError("size baseline must be the full UFS release set")
    if candidate.get("release_set") != "core":
        raise ValueError("size candidate must be the core UFS release set")
    baseline_by_architecture = {
        asset["architecture"]: asset for asset in baseline["assets"]
    }
    rows = []
    for key in RELEASE_SETS["core"]["variants"]:
        core = next(asset for asset in candidate["assets"] if asset["variant"] == key)
        full = baseline_by_architecture.get(core["architecture"])
        if full is None:
            raise ValueError(
                f"no {core['architecture']} full UFS baseline asset"
            )
        expected_full = f"{core['architecture']}-ufs-full"
        if (
            full["variant"] != expected_full
            or full["filesystem"] != "ufs"
            or full["flavor"] != "full"
        ):
            raise ValueError(
                f"{core['architecture']} baseline must be full UFS"
            )
        if core["filesystem"] != "ufs" or core["flavor"] != "core":
            raise ValueError(
                f"{core['architecture']} candidate must be core UFS"
            )
        rows.append((full, core))
    return rows


def size_reduction_percent(baseline: int, candidate: int) -> float:
    return 100.0 * (baseline - candidate) / baseline


def enforce_core_size_gate(
    rows: list[tuple[dict, dict]],
    minimum_reduction_percent: int,
) -> None:
    threshold = require_reduction_percent(minimum_reduction_percent)
    if len(rows) != len(RELEASE_SETS["core"]["variants"]):
        raise ValueError("core size gate requires both architectures")
    for full, core in rows:
        architecture = core["architecture"]
        if core["virtual_size"] > full["virtual_size"]:
            raise ValueError(f"{architecture} core virtual size regressed")
        for field, label in (
            ("allocated_size", "allocated"),
            ("compressed_size", "compressed/download"),
        ):
            # Integer cross-multiplication makes the inclusive threshold
            # boundary exact and keeps the direction visibly full -> core.
            if core[field] * 100 > full[field] * (100 - threshold):
                raise ValueError(
                    f"{architecture} core {label} size reduction is below "
                    f"{threshold}%"
                )


def compare_command(args: argparse.Namespace) -> None:
    """Report the full-versus-core size comparison for two staged sets.

    The argument roles are intentional and validated: baseline is full UFS,
    candidate is core UFS. This prevents an accidental reversal from turning a
    regression into a positive reduction.
    """
    baseline = load_publish_manifest(args.baseline)
    candidate = load_publish_manifest(args.candidate)
    rows = full_core_rows(baseline, candidate)

    lines = [
        "| Architecture | Full virtual | Core virtual | Virtual reduction | "
        "Full allocated | Core allocated | Allocated reduction | "
        "Full compressed/download | Core compressed/download | "
        "Compressed reduction | Full packages | Core packages |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
        "| ---: | ---: | ---: |",
    ]
    for full, core in rows:
        lines.append(
            f"| {core['architecture']} "
            f"| {full['virtual_size']} | {core['virtual_size']} "
            f"| {size_reduction_percent(full['virtual_size'], core['virtual_size']):.1f}% "
            f"| {full['allocated_size']} | {core['allocated_size']} "
            f"| {size_reduction_percent(full['allocated_size'], core['allocated_size']):.1f}% "
            f"| {full['compressed_size']} | {core['compressed_size']} "
            f"| {size_reduction_percent(full['compressed_size'], core['compressed_size']):.1f}% "
            f"| {full['packages']} | {core['packages']} |"
        )
    text = "\n".join(lines) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    matrix = commands.add_parser("matrix")
    matrix.add_argument("--release-set", choices=RELEASE_SETS, required=True)
    matrix.set_defaults(handler=matrix_command)

    describe = commands.add_parser("describe")
    describe.add_argument("--release-set", choices=RELEASE_SETS, required=True)
    describe.set_defaults(handler=describe_command)

    architectures = sorted({v["architecture"] for v in VARIANTS.values()})
    filesystems = sorted({v["filesystem"] for v in VARIANTS.values()})
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--architecture", choices=architectures, required=True)
    candidate.add_argument("--filesystem", choices=filesystems, required=True)
    candidate.add_argument("--flavor", choices=sorted(PACKAGE_MANIFESTS), required=True)
    candidate.add_argument("--package-manifest", type=Path, required=True)
    candidate.add_argument("--asset", type=Path, required=True)
    candidate.add_argument("--validated-sha256", required=True)
    candidate.add_argument("--virtual-size", type=int, required=True)
    candidate.add_argument(
        "--qemu-info",
        type=Path,
        required=True,
        help="trusted qemu-img info --output=json from candidate validation",
    )
    candidate.add_argument("--source-name", required=True)
    candidate.add_argument("--source-url", required=True)
    candidate.add_argument("--source-sha256", required=True)
    candidate.add_argument("--source-bytes", type=int, required=True)
    candidate.add_argument("--source-commit", required=True)
    candidate.add_argument("--qemu-version", required=True)
    candidate.add_argument("--runner", required=True)
    candidate.add_argument("--run-id", required=True)
    candidate.add_argument("--run-attempt", required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.set_defaults(handler=candidate_command)

    azure_result = commands.add_parser("azure-result")
    azure_result.add_argument("--manifest", type=Path, required=True)
    azure_result.add_argument("--asset", type=Path, required=True)
    azure_result.add_argument("--key", required=True)
    azure_result.add_argument("--source-commit", required=True)
    azure_result.add_argument("--vhd-sha256", required=True)
    azure_result.add_argument("--vhd-bytes", type=int, required=True)
    azure_result.add_argument("--contracts", required=True)
    azure_result.add_argument("--location", required=True)
    azure_result.add_argument("--vm-size", required=True)
    azure_result.add_argument("--resource-group", required=True)
    azure_result.add_argument("--run-id", required=True)
    azure_result.add_argument("--run-attempt", required=True)
    azure_result.add_argument("--output", type=Path, required=True)
    azure_result.set_defaults(handler=azure_result_command)

    stage = commands.add_parser("stage")
    stage.add_argument("--release-set", choices=RELEASE_SETS, required=True)
    stage.add_argument("--candidates", type=Path, required=True)
    stage.add_argument("--source-commit", required=True)
    stage.add_argument("--release-tag", required=True)
    stage.add_argument("--azure-results", type=Path, default=None)
    stage.add_argument(
        "--baseline",
        type=Path,
        help="staged full UFS publish manifest; required for core",
    )
    stage.add_argument(
        "--minimum-core-reduction-percent",
        type=int,
        default=CORE_MINIMUM_REDUCTION_PERCENT,
        help=(
            "minimum allocated and compressed reduction required for each "
            f"core architecture (default: {CORE_MINIMUM_REDUCTION_PERCENT})"
        ),
    )
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--notes", type=Path, required=True)
    stage.set_defaults(handler=stage_command)

    compare = commands.add_parser("compare")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--output", type=Path)
    compare.set_defaults(handler=compare_command)
    return result


def main() -> None:
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
