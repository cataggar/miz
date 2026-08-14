#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

try:
    from scripts.azure_vhd import AZURE_VHD_ALIGNMENT, VHD_FOOTER_BYTES
except ModuleNotFoundError:
    from azure_vhd import AZURE_VHD_ALIGNMENT, VHD_FOOTER_BYTES


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
        "asset_name": "FreeBSD-15.1-aarch64.ufs.qcow2",
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
        "asset_name": "FreeBSD-15.1-x86_64.ufs.qcow2",
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
        "asset_name": "FreeBSD-15.1-aarch64.qcow2",
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
        "asset_name": "FreeBSD-15.1-x86_64.qcow2",
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
    # Core variants start from the matching full profile's pinned source;
    # only the package manifest the guest realizes differs.
    "aarch64-ufs-core": {
        "architecture": "aarch64",
        "filesystem": "ufs",
        "flavor": "core",
        "source_directory": "aarch64",
        "asset_name": "FreeBSD-15.1-aarch64.ufs.core.qcow2",
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
        "asset_name": "FreeBSD-15.1-x86_64.ufs.core.qcow2",
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
    # Core ZFS variants use the same architecture-specific pinned source as
    # their full counterparts. Only the reviewed package realization differs.
    "aarch64-zfs-core": {
        "architecture": "aarch64",
        "filesystem": "zfs",
        "flavor": "core",
        "source_directory": "aarch64",
        "asset_name": "FreeBSD-15.1-aarch64.core.qcow2",
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
    "x86_64-zfs-core": {
        "architecture": "x86_64",
        "filesystem": "zfs",
        "flavor": "core",
        "source_directory": "amd64",
        "asset_name": "FreeBSD-15.1-x86_64.core.qcow2",
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
}

# The retained contract and the reviewed exclusions, mirrored from
# scripts/freebsd15_package_manifest.zig. The duplication is the point: the
# release helper validates the manifest an image actually recorded without
# trusting the builder that produced it, exactly as it does for the profile
# table. tests/freebsd15_release_test.py keeps the two in agreement.
SHARED_REQUIRED_PACKAGES = (
    "FreeBSD-set-minimal",
    "FreeBSD-runtime",
    "FreeBSD-rc",
    "FreeBSD-bsdconfig",
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
    "FreeBSD-nuageinit",
    "FreeBSD-flua",
    "FreeBSD-pkg-bootstrap",
    "FreeBSD-libarchive",
    "pkg",
    "azure-agent",
)

FILESYSTEM_REQUIRED_PACKAGES = {
    "ufs": ("FreeBSD-ufs", "FreeBSD-ufs-lib"),
    "zfs": ("FreeBSD-zfs", "FreeBSD-zfs-lib"),
}

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

PACKAGE_MANIFEST_REVISION = 3

PACKAGE_MANIFESTS = {
    filesystem: {
        "full": {
            "revision": PACKAGE_MANIFEST_REVISION,
            "required": (*SHARED_REQUIRED_PACKAGES, *required),
            "library_roots": (),
            "excluded": (),
            "excluded_classes": (),
            "prunes": False,
        },
        "core": {
            "revision": PACKAGE_MANIFEST_REVISION,
            "required": (*SHARED_REQUIRED_PACKAGES, *required),
            "library_roots": LIBRARY_ROOTS,
            "excluded": CORE_EXCLUDED_PACKAGES,
            "excluded_classes": CORE_EXCLUDED_CLASSES,
            "prunes": True,
        },
    }
    for filesystem, required in FILESYSTEM_REQUIRED_PACKAGES.items()
}

SOURCE_URL_PREFIX = (
    "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/"
)

# A release set is exactly the assets one dispatch of the release workflow is
# allowed to publish. Keeping the tag, title, and asset allowlist together is
# what lets the publisher refuse an incomplete or unexpected upload without
# consulting a second source of truth.
RELEASE_SETS = {
    "zfs": {
        "release_tag_prefix": "FreeBSD-15.1-",
        "release_title_prefix": "FreeBSD 15.1 - ",
        "requires_release_date": True,
        "variants": (
            "aarch64-zfs-full",
            "x86_64-zfs-full",
            "aarch64-zfs-core",
            "x86_64-zfs-core",
        ),
        "summary": (
            "Generalized FreeBSD 15.1-RELEASE full and core ZFS images built "
            "with zvmi."
        ),
        "highlights": (
            "Added matching AArch64 and x86_64 full and core release images.",
            "Each asset is a standalone zstd-compressed QCOW2 with no backing "
            "file.",
            "The core flavor is realized by pkg from an explicit, reviewed "
            "pkgbase manifest, not by deleting files from a full image.",
            "First boot grows the last GPT partition and onlines the enlarged "
            "`zroot` vdev; `autoexpand` keeps later enlargements working.",
            "`zpool_reguid` gives every instance a distinct pool GUID.",
        ),
    },
}

# Historical tags remain published but are not dispatchable release sets.
# Keeping their ownership explicit prevents the broad combined UFS prefix
# from targeting an existing release.
RESERVED_RELEASE_TAGS = {
    "FreeBSD-15.1-20260724": "historical full UFS release",
    "FreeBSD-15.1-zfs-20260729": "historical ZFS release",
}

AZURE_SHARED_CONTRACTS_BEFORE_STORAGE = (
    "matching-architecture-gen2",
    "key-only-ssh",
    "agent-ready",
    "hn0-dhcp",
    "serial-console",
)
AZURE_FILESYSTEM_CONTRACTS = {
    "ufs": (
        "ufs-root",
        "ufs-root-partition-growth",
        "ufs-root-filesystem-growth",
        "no-os-disk-swap",
    ),
    "zfs": (
        "zfs-root",
        "zpool-healthy",
    ),
}
AZURE_SHARED_CONTRACTS_AFTER_STORAGE = (
    "root-growth",
    "gpt-healthy",
    "reboot-reconnect",
    "instance-identity",
)
AZURE_CONTRACTS = (
    *AZURE_SHARED_CONTRACTS_BEFORE_STORAGE,
    *AZURE_FILESYSTEM_CONTRACTS["zfs"],
    *AZURE_SHARED_CONTRACTS_AFTER_STORAGE,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RELEASE_DATE_RE = re.compile(r"^[0-9]{8}$")
CANDIDATE_SCHEMA = 3
# Core publication requires at least this reduction in both qemu-img's
# allocated size and the downloadable compressed file size. Validation of both
# architectures measured reductions above 72%, so ten percent is a conservative
# fail-closed floor while the reviewed package manifest—not an aggressive size
# target—remains the primary definition of "core".
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


def package_manifest(filesystem: str, flavor: str) -> dict:
    if filesystem not in PACKAGE_MANIFESTS:
        raise ValueError(f"unsupported FreeBSD filesystem: {filesystem}")
    if flavor not in PACKAGE_MANIFESTS[filesystem]:
        raise ValueError(f"unsupported FreeBSD flavor: {flavor}")
    return PACKAGE_MANIFESTS[filesystem][flavor]


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


def verify_package_manifest(
    filesystem: str,
    flavor: str,
    packages: list[dict],
) -> None:
    """Check a recorded manifest for the selected filesystem and flavor.

    The builder already did this, but the release helper must be able to
    reject a candidate without trusting the builder that produced it.
    """
    manifest = package_manifest(filesystem, flavor)
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


def require_release_date(value: object) -> str:
    if not isinstance(value, str) or not RELEASE_DATE_RE.fullmatch(value):
        raise ValueError("release date must be an explicit YYYYMMDD value")
    try:
        datetime.strptime(value, "%Y%m%d")
    except ValueError as error:
        raise ValueError("release date is not a valid calendar date") from error
    return value


def release_identity(
    name: str,
    release_date: str | None = None,
) -> tuple[str, str]:
    selected = release_set(name)
    if selected.get("requires_release_date"):
        reviewed_date = require_release_date(release_date)
        identity = (
            selected["release_tag_prefix"] + reviewed_date,
            selected["release_title_prefix"] + reviewed_date,
        )
        if identity[0] in RESERVED_RELEASE_TAGS:
            raise ValueError(
                f"{identity[0]} belongs to "
                f"{RESERVED_RELEASE_TAGS[identity[0]]}"
            )
        return identity
    if release_date not in (None, ""):
        raise ValueError("release date is not applicable to this release set")
    return selected["release_tag"], selected["release_title"]


def validate_release_tag(name: str, tag: object) -> None:
    selected = release_set(name)
    if not isinstance(tag, str):
        raise ValueError("release tag must be a string")
    if selected.get("requires_release_date"):
        prefix = selected["release_tag_prefix"]
        if not tag.startswith(prefix):
            raise ValueError(f"{name} release tag does not match release set")
        expected, _ = release_identity(name, tag.removeprefix(prefix))
        if tag != expected:
            raise ValueError(f"{name} release tag does not match release set")
    elif tag != selected["release_tag"]:
        raise ValueError(f"{name} release tag does not match release set")


def build_variants(name: str) -> tuple[str, ...]:
    return release_set(name)["variants"]


def azure_variants(name: str) -> tuple[str, ...]:
    return release_set(name)["variants"]


def azure_contracts(filesystem: str) -> tuple[str, ...]:
    if filesystem not in AZURE_FILESYSTEM_CONTRACTS:
        raise ValueError(f"unsupported Azure filesystem contract: {filesystem}")
    return (
        *AZURE_SHARED_CONTRACTS_BEFORE_STORAGE,
        *AZURE_FILESYSTEM_CONTRACTS[filesystem],
        *AZURE_SHARED_CONTRACTS_AFTER_STORAGE,
    )


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
    include = []
    for key in build_variants(args.release_set):
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
                "release_role": "release",
            }
        )
    print(json.dumps({"include": include}, sort_keys=True))


def azure_matrix_command(args: argparse.Namespace) -> None:
    include = []
    for key in azure_variants(args.release_set):
        variant = VARIANTS[key]
        if variant["architecture"] == "aarch64":
            location_variable = "AZURE_LOCATION_ARM64"
            size_variable = "AZURE_VM_SIZE_ARM64"
        else:
            location_variable = "AZURE_LOCATION_X64"
            size_variable = "AZURE_VM_SIZE_X64"
        include.append(
            {
                "key": key,
                "architecture": variant["architecture"],
                "filesystem": variant["filesystem"],
                "flavor": variant["flavor"],
                "asset_name": variant["asset_name"],
                "location_variable": location_variable,
                "size_variable": size_variable,
            }
        )
    print(json.dumps({"include": include}, sort_keys=True))


def describe_command(args: argparse.Namespace) -> None:
    selected = release_set(args.release_set)
    release_tag, release_title = release_identity(
        args.release_set,
        getattr(args, "release_date", None),
    )
    print(f"release_tag={release_tag}")
    print(f"release_title={release_title}")
    print(f"asset_count={len(selected['variants'])}")
    print(
        "core_minimum_reduction_percent="
        f"{CORE_MINIMUM_REDUCTION_PERCENT}"
    )


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
    qemu_info_path = args.qemu_info.resolve(strict=True)
    if qemu_info_path.parent != asset.parent:
        raise ValueError("qemu-img validation input must be beside the candidate")
    qemu_image = load_qemu_image_info(qemu_info_path, args.virtual_size)
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
    verify_package_manifest(expected["filesystem"], expected["flavor"], packages)

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
            "manifest_revision": package_manifest(
                expected["filesystem"], expected["flavor"]
            )["revision"],
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
            "qemu_info": {
                "name": qemu_info_path.name,
                "sha256": sha256(qemu_info_path),
            },
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
    expected_contracts = list(azure_contracts(candidate["filesystem"]))
    # Independently verify the asset the caller points to is the same file the
    # candidate manifest describes — the harness may pass a path that differs
    # from the one validate_candidate resolved (same file, different argument).
    asset = args.asset.resolve(strict=True)
    if asset != asset_path.resolve():
        actual_asset_sha256 = sha256(asset)
        if actual_asset_sha256 != candidate["asset_sha256"]:
            raise ValueError("--asset does not match the candidate digest")
    require_sha256(args.vhd_sha256, "VHD SHA-256")
    if (
        args.vhd_current_size <= 0
        or args.vhd_current_size % AZURE_VHD_ALIGNMENT != 0
        or args.vhd_bytes != args.vhd_current_size + VHD_FOOTER_BYTES
    ):
        raise ValueError("VHD size evidence is inconsistent")
    # Validate contracts passed as a comma-separated string.
    provided_contracts = [c.strip() for c in args.contracts.split(",")]
    if provided_contracts != expected_contracts:
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
    candidate_workflow = candidate["validation"]
    if (
        workflow_run_id != candidate_workflow["run_id"]
        or workflow_run_attempt != candidate_workflow["run_attempt"]
    ):
        raise ValueError(
            "Azure result workflow identity does not match candidate validation"
        )

    document = {
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-azure-acceptance",
        "variant": candidate["variant"],
        "architecture": candidate["architecture"],
        "filesystem": candidate["filesystem"],
        "flavor": candidate["flavor"],
        "asset_name": candidate["asset_name"],
        "source_commit": args.source_commit,
        "qcow_sha256": candidate["asset_sha256"],
        "qcow_virtual_size": candidate["virtual_size"],
        "qcow_allocated_size": candidate["allocated_size"],
        "qcow_compressed_size": candidate["compressed_size"],
        "derived_vhd_sha256": args.vhd_sha256,
        "derived_vhd_bytes": args.vhd_bytes,
        "derived_vhd_current_size": args.vhd_current_size,
        "status": "success",
        "location": location,
        "vm_size": vm_size,
        "resource_group": resource_group,
        "contracts": expected_contracts,
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
    qemu_info = validation.get("qemu_info")
    if not isinstance(qemu_info, dict):
        raise ValueError(f"{manifest_path}: qemu-img validation input is missing")
    qemu_info_name = qemu_info.get("name")
    if (
        not isinstance(qemu_info_name, str)
        or not qemu_info_name
        or Path(qemu_info_name).name != qemu_info_name
    ):
        raise ValueError(f"{manifest_path}: invalid qemu-img validation input name")
    require_sha256(
        qemu_info.get("sha256", ""),
        f"{manifest_path}: qemu-img validation input SHA-256",
    )
    qemu_info_path = manifest_path.parent / qemu_info_name
    if not qemu_info_path.is_file():
        raise ValueError(f"{manifest_path}: qemu-img validation input is missing")
    if sha256(qemu_info_path) != qemu_info["sha256"]:
        raise ValueError(f"{manifest_path}: qemu-img validation input mismatch")
    if load_qemu_image_info(
        qemu_info_path,
        document["virtual_size"],
    ) != qemu_image:
        raise ValueError(f"{manifest_path}: qemu-img validation input changed")
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
    reviewed = package_manifest(expected["filesystem"], expected["flavor"])
    if recorded.get("manifest_revision") != reviewed["revision"]:
        raise ValueError(
            f"{manifest_path}: package manifest revision does not match"
        )
    if recorded.get("count") != len(recorded["names"]):
        raise ValueError(f"{manifest_path}: package count does not match")
    verify_package_manifest(
        expected["filesystem"],
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
    core_rows: list[tuple[dict, dict]] | None = None,
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
        ]
    )
    if core_rows is not None:
        lines.extend(
            [
                "",
                f"## Full {candidates[0]['filesystem'].upper()} versus core evidence",
                "",
                "| Architecture | Full virtual | Core virtual | "
                "Virtual reduction | Full allocated | Core allocated | "
                "Allocated reduction | Full compressed/download | "
                "Core compressed/download | Compressed reduction | "
                "Full packages | Core packages | Full SHA-256 | "
                "Core SHA-256 |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
                "| ---: | ---: | ---: | ---: | --- | --- |",
            ]
        )
        for full, core in core_rows:
            lines.append(
                f"| {core['architecture']} "
                f"| {full['virtual_size']} | {core['virtual_size']} "
                f"| {size_reduction_percent(full['virtual_size'], core['virtual_size']):.1f}% "
                f"| {full['allocated_size']} | {core['allocated_size']} "
                f"| {size_reduction_percent(full['allocated_size'], core['allocated_size']):.1f}% "
                f"| {full['compressed_size']} | {core['compressed_size']} "
                "| "
                f"{size_reduction_percent(full['compressed_size'], core['compressed_size']):.1f}% "
                f"| {full['packages']} | {core['packages']} "
                f"| `{full['sha256']}` | `{core['sha256']}` |"
            )
        lines.extend(
            [
                "",
                f"Both architectures passed the staging gate requiring at "
                f"least {minimum_core_reduction_percent}% reduction in "
                "qemu-img allocated size and compressed/download size. Core "
                "virtual size may not exceed its matching same-source full "
                f"{candidates[0]['filesystem'].upper()} asset.",
            ]
        )
    if any(candidate["flavor"] == "core" for candidate in candidates):
        filesystem = candidates[0]["filesystem"]
        manifest = package_manifest(filesystem, "core")
        lines.extend(
            [
                "",
                "## Core package contract",
                "",
                f"- Reviewed manifest revision: {manifest['revision']}",
                "- The core package set is dependency-closed and realized by "
                "`pkg`; it is not produced by ad hoc deletion from a full "
                "image.",
                "- Retained package roots:",
                "",
                "```",
                *manifest["required"],
                *manifest["library_roots"],
                "```",
                "",
                "- Reviewed package exclusions:",
                "",
                "```",
                *manifest["excluded"],
                "```",
                "",
                "- Excluded FreeBSD pkgbase name classes: "
                + ", ".join(f"`{name}`" for name in manifest["excluded_classes"]),
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
                f"`{validation['runner']}`; passed dual-instance UEFI "
                "provisioning, SSH, reboot, identity separation, disk growth, "
                "and clean shutdown.",
            ]
        )
    if core_rows is not None:
        lines.extend(
            [
                f"- Full and core {candidates[0]['filesystem'].upper()} "
                "candidates were built in this dispatch "
                "from the same source commit and the same "
                "architecture-specific pinned source name, URL, and "
                "SHA-256.",
            ]
        )
    if azure_results is not None:
        lines.extend(
            [
                "",
                "## Azure validation",
                "",
                "- Exact-candidate matching-architecture Gen2 validation is "
                "complete for every published release asset.",
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
                    f"  - Derived VHD current size: "
                    f"{azure['derived_vhd_current_size']} bytes",
                    "  - Passed contracts: "
                    + ", ".join(
                        f"`{contract}`" for contract in azure["contracts"]
                    ),
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
            "No `.sha256` or package-manifest sidecar assets are published.",
            "",
        ]
    )
    return "\n".join(lines)


def stage_command(args: argparse.Namespace) -> None:
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise ValueError("source commit must be a lowercase 40-character SHA")
    selected = release_set(args.release_set)
    expected_release_tag, _ = release_identity(
        args.release_set,
        getattr(args, "release_date", None),
    )
    if args.release_tag != expected_release_tag:
        raise ValueError(
            f"{args.release_set} releases must be tagged "
            f"{expected_release_tag}"
        )
    if args.azure_results is None:
        raise ValueError(f"{args.release_set} releases require --azure-results")

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
    core_rows = full_core_rows({
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-release",
        "release_set": args.release_set,
        "release_tag": expected_release_tag,
        "source_commit": args.source_commit,
        "assets": [
            candidate_release_asset(by_variant[key]) for key in wanted
        ],
    })
    enforce_core_size_gate(core_rows, minimum_reduction)
    azure_manifests = sorted(args.azure_results.rglob("azure-result.json"))
    if len(azure_manifests) != len(wanted):
        raise ValueError(f"expected {len(wanted)} azure result manifests")
    azure_by_variant = {}
    for azure_manifest in azure_manifests:
        document = json.loads(azure_manifest.read_text(encoding="utf-8"))
        if document.get("schema") != CANDIDATE_SCHEMA:
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
        if document.get("source_commit") != args.source_commit:
            raise ValueError(f"{azure_manifest}: source commit mismatch")
        if document.get("qcow_sha256") != candidate["asset_sha256"]:
            raise ValueError(
                f"{azure_manifest}: QCOW SHA-256 does not match candidate"
            )
        for field in ("virtual_size", "allocated_size", "compressed_size"):
            if document.get(f"qcow_{field}") != candidate[field]:
                raise ValueError(
                    f"{azure_manifest}: QCOW {field} does not match candidate"
                )
        if document.get("status") != "success":
            raise ValueError(f"{azure_manifest}: status is not success")
        derived_vhd_bytes = document.get("derived_vhd_bytes")
        derived_vhd_current_size = document.get(
            "derived_vhd_current_size"
        )
        if (
            not isinstance(derived_vhd_bytes, int)
            or not isinstance(derived_vhd_current_size, int)
            or derived_vhd_current_size <= 0
            or derived_vhd_current_size % AZURE_VHD_ALIGNMENT != 0
            or derived_vhd_bytes
            != derived_vhd_current_size + VHD_FOOTER_BYTES
        ):
            raise ValueError(
                f"{azure_manifest}: derived VHD size evidence is inconsistent"
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
        if document.get("contracts") != list(
            azure_contracts(candidate["filesystem"])
        ):
            raise ValueError(
                f"{azure_manifest}: contracts do not match required Azure contracts"
            )
        workflow = document.get("workflow")
        if not isinstance(workflow, dict):
            raise ValueError(f"{azure_manifest}: workflow is missing")
        workflow_run_id = require_non_empty(
            str(workflow.get("run_id", "")),
            "run_id",
        )
        workflow_run_attempt = require_non_empty(
            str(workflow.get("run_attempt", "")),
            "run_attempt",
        )
        candidate_workflow = candidate["validation"]
        if (
            workflow_run_id != candidate_workflow["run_id"]
            or workflow_run_attempt != candidate_workflow["run_attempt"]
        ):
            raise ValueError(
                f"{azure_manifest}: workflow identity does not match candidate"
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
                "derived_vhd_current_size": azure[
                    "derived_vhd_current_size"
                ],
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
                minimum_reduction
            ),
            core_rows=core_rows,
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
        "package_manifest": candidate["packages"],
        "source": candidate["source"],
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
    validate_release_tag(release_set_name, document.get("release_tag"))
    if not COMMIT_RE.fullmatch(str(document.get("source_commit", ""))):
        raise ValueError(f"{path}: invalid source commit")
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
        package_count = require_positive_int(
            asset.get("packages"),
            f"{path}: {key} package count",
        )
        package_record = asset.get("package_manifest")
        if not isinstance(package_record, dict):
            raise ValueError(f"{path}: {key} package manifest is missing")
        reviewed = package_manifest(expected["filesystem"], expected["flavor"])
        if package_record.get("manifest_revision") != reviewed["revision"]:
            raise ValueError(f"{path}: {key} package manifest revision mismatch")
        if package_record.get("count") != package_count:
            raise ValueError(f"{path}: {key} package manifest count mismatch")
        package_names = package_record.get("names")
        if not isinstance(package_names, list) or len(package_names) != package_count:
            raise ValueError(f"{path}: {key} package names are incomplete")
        if (
            any(not isinstance(name, str) or not name for name in package_names)
            or len(set(package_names)) != package_count
        ):
            raise ValueError(f"{path}: {key} package names are invalid or duplicate")
        require_positive_int(
            package_record.get("installed_bytes"),
            f"{path}: {key} installed package bytes",
        )
        verify_package_manifest(
            expected["filesystem"],
            expected["flavor"],
            [{"name": name} for name in package_names],
        )
        source = asset.get("source")
        if not isinstance(source, dict):
            raise ValueError(f"{path}: {key} source metadata is missing")
        for field in ("name", "sha256"):
            if source.get(field) != expected[f"source_{field}"]:
                raise ValueError(f"{path}: {key} source {field} does not match")
        if source.get("url") != source_url(key):
            raise ValueError(f"{path}: {key} source URL does not match")
        require_positive_int(source.get("bytes"), f"{path}: {key} source bytes")
        by_variant[key] = asset
    if set(by_variant) != set(selected["variants"]):
        raise ValueError(f"{path}: release asset matrix is incomplete or unexpected")
    return document


def full_core_rows(release_manifest: dict) -> list[tuple[dict, dict]]:
    """Pair full and core assets for the selected release filesystem."""
    release_set_name = release_manifest.get("release_set")
    selected = release_set(release_set_name)
    filesystems = {VARIANTS[key]["filesystem"] for key in selected["variants"]}
    if len(filesystems) != 1:
        raise ValueError("size comparison requires one release filesystem")
    filesystem = filesystems.pop()
    by_variant = {
        asset["variant"]: asset for asset in release_manifest["assets"]
    }
    rows = []
    core_variants = tuple(
        key
        for key in selected["variants"]
        if VARIANTS[key]["flavor"] == "core"
    )
    for key in core_variants:
        core = by_variant.get(key)
        core_profile = VARIANTS[key]
        if core is None:
            raise ValueError(
                f"no {core_profile['architecture']} core "
                f"{filesystem.upper()} asset"
            )
        if any(
            core.get(field) != core_profile[field]
            for field in ("architecture", "filesystem", "flavor")
        ):
            raise ValueError(f"{key} core asset identity is invalid")
        expected_full = f"{core_profile['architecture']}-{filesystem}-full"
        full = by_variant.get(expected_full)
        if full is None:
            raise ValueError(
                f"no {core_profile['architecture']} full "
                f"{filesystem.upper()} asset"
            )
        full_profile = VARIANTS[expected_full]
        if (
            full["variant"] != expected_full
            or any(
                full.get(field) != full_profile[field]
                for field in ("architecture", "filesystem", "flavor")
            )
        ):
            raise ValueError(
                f"{core_profile['architecture']} paired asset identity is invalid"
            )
        if (
            core["variant"] != key
        ):
            raise ValueError(
                f"{core_profile['architecture']} core asset identity is invalid"
            )
        if full["source"] != core["source"]:
            raise ValueError(
                f"{core['architecture']} full and core pinned sources differ"
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
    if len(rows) != 2:
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
    """Report the full-versus-core size comparison within one staged set."""
    candidate = load_publish_manifest(args.candidate)
    rows = full_core_rows(candidate)

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

    azure_matrix = commands.add_parser("azure-matrix")
    azure_matrix.add_argument(
        "--release-set",
        choices=RELEASE_SETS,
        required=True,
    )
    azure_matrix.set_defaults(handler=azure_matrix_command)

    describe = commands.add_parser("describe")
    describe.add_argument("--release-set", choices=RELEASE_SETS, required=True)
    describe.add_argument("--release-date")
    describe.set_defaults(handler=describe_command)

    architectures = sorted({v["architecture"] for v in VARIANTS.values()})
    filesystems = sorted({v["filesystem"] for v in VARIANTS.values()})
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--architecture", choices=architectures, required=True)
    candidate.add_argument("--filesystem", choices=filesystems, required=True)
    candidate.add_argument("--flavor", choices=("core", "full"), required=True)
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
    azure_result.add_argument("--vhd-current-size", type=int, required=True)
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
    stage.add_argument("--release-date")
    stage.add_argument("--azure-results", type=Path, default=None)
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
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--output", type=Path)
    compare.set_defaults(handler=compare_command)
    return result


def main() -> None:
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
