#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


# One entry per architecture x root filesystem the FreeBSD builder can
# produce. These values duplicate the Zig builder's profile table on purpose:
# the release workflow must be able to reject a candidate without trusting the
# builder that produced it. tests/freebsd15_release_test.py keeps the two
# tables in agreement.
VARIANTS = {
    "aarch64-ufs": {
        "architecture": "aarch64",
        "filesystem": "ufs",
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
    "x86_64-ufs": {
        "architecture": "x86_64",
        "filesystem": "ufs",
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
    "aarch64-zfs": {
        "architecture": "aarch64",
        "filesystem": "zfs",
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
    "x86_64-zfs": {
        "architecture": "x86_64",
        "filesystem": "zfs",
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
        "variants": ("aarch64-ufs", "x86_64-ufs"),
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
        "variants": ("aarch64-zfs", "x86_64-zfs"),
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
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CANDIDATE_SCHEMA = 2
PROFILE_KEYS = (
    "architecture",
    "filesystem",
    "asset_name",
    "virtual_size",
)


def variant_key(architecture: str, filesystem: str) -> str:
    key = f"{architecture}-{filesystem}"
    if key not in VARIANTS:
        raise ValueError(f"unsupported FreeBSD variant: {key}")
    return key


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
    key = variant_key(args.architecture, args.filesystem)
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

    document = {
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-candidate",
        "variant": key,
        "architecture": expected["architecture"],
        "filesystem": expected["filesystem"],
        "asset_name": asset.name,
        "asset_bytes": asset.stat().st_size,
        "asset_sha256": actual_sha256,
        "virtual_size": args.virtual_size,
        "source": {
            "name": args.source_name,
            "url": args.source_url,
            "bytes": args.source_bytes,
            "sha256": args.source_sha256,
        },
        "source_commit": args.source_commit,
        "validation": {
            "qemu_version": args.qemu_version.strip(),
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
    if asset.stat().st_size != document.get("asset_bytes"):
        raise ValueError(f"{manifest_path}: candidate size mismatch")
    if sha256(asset) != document.get("asset_sha256"):
        raise ValueError(f"{manifest_path}: candidate digest mismatch")
    require_sha256(document["asset_sha256"], "candidate SHA-256")
    require_sha256(document["source"]["sha256"], "source SHA-256")
    return document, asset


def release_notes(
    selected: dict,
    candidates: list[dict],
    source_commit: str,
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
            "| Architecture | Root | Asset | File size | Virtual size | SHA-256 |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for candidate in candidates:
        lines.append(
            "| {architecture} | {filesystem} | `{asset_name}` | {asset_bytes} "
            "| {virtual_size} | `{asset_sha256}` |".format(**candidate)
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
    lines.extend(
        [
            "",
            "The QCOW2 assets are not directly uploadable to Azure. Derive an "
            "aligned fixed VHD with `zvmi azure derive` before upload. The exact "
            "release candidates were validated under UEFI QEMU; this release "
            "does not claim exact-candidate Azure validation.",
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

    args.output.mkdir(parents=True, exist_ok=True)
    candidates = [by_variant[key] for key in wanted]
    for candidate in candidates:
        destination = args.output / candidate["asset_name"]
        if destination.exists():
            raise ValueError(f"staged asset already exists: {destination}")
        shutil.copyfile(assets[candidate["variant"]], destination)
        if sha256(destination) != candidate["asset_sha256"]:
            raise ValueError("staged asset digest mismatch")

    manifest = {
        "schema": CANDIDATE_SCHEMA,
        "type": "zvmi-freebsd15-release",
        "release_set": args.release_set,
        "release_tag": args.release_tag,
        "source_commit": args.source_commit,
        "assets": [
            {
                "variant": candidate["variant"],
                "architecture": candidate["architecture"],
                "filesystem": candidate["filesystem"],
                "asset_name": candidate["asset_name"],
                "bytes": candidate["asset_bytes"],
                "sha256": candidate["asset_sha256"],
            }
            for candidate in candidates
        ],
    }
    (args.output / "publish-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.notes.write_text(
        release_notes(selected, candidates, args.source_commit),
        encoding="utf-8",
    )


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
    candidate.add_argument("--asset", type=Path, required=True)
    candidate.add_argument("--validated-sha256", required=True)
    candidate.add_argument("--virtual-size", type=int, required=True)
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

    stage = commands.add_parser("stage")
    stage.add_argument("--release-set", choices=RELEASE_SETS, required=True)
    stage.add_argument("--candidates", type=Path, required=True)
    stage.add_argument("--source-commit", required=True)
    stage.add_argument("--release-tag", required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--notes", type=Path, required=True)
    stage.set_defaults(handler=stage_command)
    return result


def main() -> None:
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
