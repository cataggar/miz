#!/usr/bin/env python3
"""Validate fixed VHD geometry for Azure uploads."""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path


AZURE_VHD_ALIGNMENT = 1024 * 1024
VHD_FOOTER_BYTES = 512
VHD_MAX_CHS_SECTORS = 65535 * 16 * 255


def fail(message: str) -> None:
    raise SystemExit(message)


@dataclass(frozen=True)
class AzureVhdGeometry:
    current_size: int
    file_size: int
    qemu_virtual_size: int


def fixed_vhd_geometry(current_size: int) -> tuple[int, int, int]:
    total_sectors = min(current_size // 512, VHD_MAX_CHS_SECTORS)
    if total_sectors >= 65535 * 16 * 63:
        sectors_per_track = 255
        heads = 16
        cylinders_times_heads = total_sectors // sectors_per_track
    else:
        sectors_per_track = 17
        cylinders_times_heads = total_sectors // sectors_per_track
        heads = max((cylinders_times_heads + 1023) // 1024, 4)
        if cylinders_times_heads >= heads * 1024 or heads > 16:
            sectors_per_track = 31
            heads = 16
            cylinders_times_heads = total_sectors // sectors_per_track
        if cylinders_times_heads >= heads * 1024:
            sectors_per_track = 63
            heads = 16
            cylinders_times_heads = total_sectors // sectors_per_track
    return cylinders_times_heads // heads, heads, sectors_per_track


def validate_azure_vhd_footer(
    file_size: int,
    footer: bytes,
) -> tuple[int, int]:
    if len(footer) != VHD_FOOTER_BYTES:
        fail("derived upload VHD is truncated before its complete footer")
    if footer[:8] != b"conectix":
        fail("derived upload VHD footer cookie is invalid")

    stored_checksum = struct.unpack_from(">I", footer, 64)[0]
    checked = bytearray(footer)
    checked[64:68] = b"\0" * 4
    expected_checksum = (~sum(checked)) & 0xFFFFFFFF
    if stored_checksum != expected_checksum:
        fail("derived upload VHD footer checksum is invalid")

    features, version = struct.unpack_from(">II", footer, 8)
    data_offset = struct.unpack_from(">Q", footer, 16)[0]
    creator_version = struct.unpack_from(">I", footer, 32)[0]
    original_size, current_size = struct.unpack_from(">QQ", footer, 40)
    cylinders, heads, sectors_per_track = struct.unpack_from(">HBB", footer, 56)
    disk_type = struct.unpack_from(">I", footer, 60)[0]
    if features != 2 or version != 0x00010000:
        fail("derived upload VHD footer version is invalid")
    if (
        footer[28:32] != b"miz\0"
        or creator_version != 0x00010000
        or footer[36:40] != b"\0" * 4
    ):
        fail("derived upload VHD creator identity is invalid")
    if data_offset != 0xFFFFFFFFFFFFFFFF or disk_type != 2:
        fail("derived upload VHD is not fixed")
    if original_size != current_size:
        fail("derived upload VHD original and current sizes differ")
    if footer[84] != 0 or any(footer[85:]):
        fail("derived upload VHD footer state or reserved bytes are invalid")
    if current_size <= 0 or current_size % AZURE_VHD_ALIGNMENT != 0:
        fail("derived upload VHD current size is not 1 MiB aligned")
    if file_size != current_size + VHD_FOOTER_BYTES:
        fail("derived upload VHD file size does not equal current size plus footer")

    expected_geometry = fixed_vhd_geometry(current_size)
    if (cylinders, heads, sectors_per_track) != expected_geometry:
        fail("derived upload VHD CHS geometry is invalid")
    geometry_sectors = cylinders * heads * sectors_per_track
    qemu_virtual_size = (
        current_size
        if geometry_sectors == VHD_MAX_CHS_SECTORS
        else geometry_sectors * 512
    )
    return current_size, qemu_virtual_size


def validate_azure_vhd_info(
    info: dict[str, object],
    file_size: int,
    footer: bytes,
) -> int:
    if info.get("format") != "vpc":
        fail("derived upload image is not VHD/VPC")
    reported_size = info.get("virtual-size")
    if type(reported_size) is not int or reported_size <= 0:
        fail("derived upload VHD reported virtual size is invalid")

    current_size, expected_reported_size = validate_azure_vhd_footer(
        file_size,
        footer,
    )
    allowed_reported_sizes = {current_size, expected_reported_size}
    if reported_size not in allowed_reported_sizes:
        fail(
            "derived upload VHD qemu virtual size is incompatible with "
            "footer current size and legacy CHS rounding: "
            f"reported={reported_size} current={current_size} "
            f"allowed={sorted(allowed_reported_sizes)}"
        )
    return current_size


def inspect_azure_vhd(info_path: Path, vhd_path: Path) -> AzureVhdGeometry:
    vhd = vhd_path.resolve()
    if not vhd.is_file():
        fail(f"derived VHD is missing: {vhd}")
    file_size = vhd.stat().st_size
    if file_size < VHD_FOOTER_BYTES:
        fail("derived upload VHD is truncated before its complete footer")
    try:
        with vhd.open("rb") as stream:
            stream.seek(-VHD_FOOTER_BYTES, 2)
            footer = stream.read(VHD_FOOTER_BYTES)
    except OSError as error:
        fail(f"cannot read derived VHD footer: {error}")
    try:
        info = json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {info_path}: {error}")
    if not isinstance(info, dict):
        fail(f"{info_path} must contain a JSON object")
    current_size = validate_azure_vhd_info(info, file_size, footer)
    return AzureVhdGeometry(
        current_size=current_size,
        file_size=file_size,
        qemu_virtual_size=info["virtual-size"],
    )


def verify_command(args: argparse.Namespace) -> None:
    geometry = inspect_azure_vhd(args.info, args.vhd)
    print(geometry.current_size)
    print(geometry.file_size)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--info", type=Path, required=True)
    verify.add_argument("--vhd", type=Path, required=True)
    verify.set_defaults(function=verify_command)
    return result


def main() -> None:
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
