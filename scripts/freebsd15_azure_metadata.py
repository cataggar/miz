#!/usr/bin/env python3
"""Validate Azure metadata used by the FreeBSD acceptance harness."""

import json
import re
import sys

GIB = 1024**3


def same(left, right):
    return isinstance(left, str) and left.casefold() == right.casefold()


def load_document(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def value_at(document, path):
    value = document
    for component in path.split("."):
        if not isinstance(value, dict) or component not in value:
            return False, None
        value = value[component]
    return True, value


def validate_size(document, scope, expected_size_gib, byte_paths, gib_paths,
                  allow_missing=False):
    expected_gib = int(expected_size_gib)
    expected_bytes = expected_gib * GIB
    observed = {}
    represented = 0
    mismatches = []

    for path, expected in (
        *((path, expected_bytes) for path in byte_paths),
        *((path, expected_gib) for path in gib_paths),
    ):
        present, value = value_at(document, path)
        if present:
            observed[path] = value
        if not present or value is None:
            continue
        represented += 1
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            mismatches.append(path)

    if mismatches:
        raise SystemExit(
            f"{scope} size mismatch: expected {expected_gib} GiB "
            f"({expected_bytes} bytes); observed "
            f"{json.dumps(observed, sort_keys=True)}; mismatched fields "
            f"{', '.join(mismatches)}"
        )
    if represented == 0 and not allow_missing:
        raise SystemExit(
            f"{scope} size metadata is missing: expected {expected_gib} GiB "
            f"({expected_bytes} bytes); observed "
            f"{json.dumps(observed, sort_keys=True)}; object keys "
            f"{sorted(document) if isinstance(document, dict) else '<non-object>'}"
        )


def validate_managed_disk(argv):
    (
        path,
        expected_id,
        expected_name,
        expected_group,
        expected_location,
        expected_architecture,
        expected_size_gib,
    ) = argv
    document = load_document(path)

    if not same(document.get("id"), expected_id):
        raise SystemExit("Azure returned a different managed disk identity")
    if document.get("name") != expected_name:
        raise SystemExit("Azure returned a different managed disk name")
    resource_group = document.get("resourceGroup")
    if resource_group not in (None, "") and not same(resource_group, expected_group):
        raise SystemExit("managed disk is outside the owned temporary resource group")
    if not same(document.get("location"), expected_location):
        raise SystemExit("managed disk location mismatch")
    if not same(document.get("type"), "Microsoft.Compute/disks"):
        raise SystemExit("Azure returned a non-disk resource")
    if document.get("osType") != "Linux":
        raise SystemExit("managed disk OS type mismatch")
    if document.get("hyperVGeneration") != "V2":
        raise SystemExit("managed disk is not Gen2")
    supported = document.get("supportedCapabilities")
    if (
        not isinstance(supported, dict)
        or supported.get("architecture") != expected_architecture
    ):
        raise SystemExit("managed disk architecture mismatch")
    if document.get("diskState") != "Unattached":
        raise SystemExit("managed disk is not safely detached after upload")
    if document.get("provisioningState") != "Succeeded":
        raise SystemExit("managed disk provisioning did not succeed")
    validate_size(
        document,
        "managed disk expansion",
        expected_size_gib,
        ("diskSizeBytes", "sizeInBytes"),
        ("diskSizeGb", "diskSizeGB", "sizeInGB", "sizeInGb"),
    )
    print(document["id"])


def validate_gallery(argv):
    (
        path,
        expected_id,
        expected_name,
        expected_group,
        expected_location,
    ) = argv
    document = load_document(path)

    if not same(document.get("id"), expected_id):
        raise SystemExit("Azure returned a different gallery identity")
    if document.get("name") != expected_name:
        raise SystemExit("Azure returned a different gallery name")
    resource_group = document.get("resourceGroup")
    if resource_group not in (None, "") and not same(resource_group, expected_group):
        raise SystemExit("gallery is outside the owned temporary resource group")
    if not same(document.get("location"), expected_location):
        raise SystemExit("gallery location mismatch")
    if not same(document.get("type"), "Microsoft.Compute/galleries"):
        raise SystemExit("Azure returned a non-gallery resource")
    if document.get("provisioningState") != "Succeeded":
        raise SystemExit("temporary gallery provisioning did not succeed")

    present, sharing = value_at(document, "sharingProfile")
    if present and sharing is not None:
        if not isinstance(sharing, dict):
            raise SystemExit("temporary gallery sharing metadata is invalid")
        permissions = sharing.get("permissions")
        if permissions is not None and not same(permissions, "Private"):
            raise SystemExit("temporary gallery is not private")
        for field in ("groups", "communityGalleryInfo"):
            if sharing.get(field) not in (None, "", [], {}):
                raise SystemExit("temporary gallery exposes shared metadata")


def validate_gallery_image_version(argv):
    (
        path,
        expected_id,
        expected_name,
        expected_group,
        expected_location,
        expected_location_display_name,
        expected_disk_id,
        expected_size_gib,
    ) = argv
    document = load_document(path)

    def same_location(value):
        return isinstance(value, str) and value.casefold() in (
            expected_location.casefold(),
            expected_location_display_name.casefold(),
        )

    if not same(document.get("id"), expected_id):
        raise SystemExit("Azure returned a different gallery image-version identity")
    if document.get("name") != expected_name:
        raise SystemExit("Azure returned a different gallery image-version name")
    resource_group = document.get("resourceGroup")
    if resource_group not in (None, "") and not same(resource_group, expected_group):
        raise SystemExit("image version is outside the owned temporary resource group")
    if not same(document.get("location"), expected_location):
        raise SystemExit("gallery image-version location mismatch")
    if not same(document.get("type"), "Microsoft.Compute/galleries/images/versions"):
        raise SystemExit("Azure returned a non-gallery-image-version resource")
    if document.get("provisioningState") != "Succeeded":
        raise SystemExit("gallery image-version provisioning did not succeed")

    storage = document.get("storageProfile")
    if not isinstance(storage, dict):
        raise SystemExit("gallery image-version storage profile is missing")
    os_disk = storage.get("osDiskImage")
    if not isinstance(os_disk, dict):
        raise SystemExit("gallery image-version OS disk metadata is missing")

    source_ids = {}
    for path, source in (
        ("storageProfile.osDiskImage.source", os_disk.get("source")),
        ("storageProfile.source", storage.get("source")),
    ):
        if source is None:
            continue
        if not isinstance(source, dict):
            raise SystemExit(
                f"gallery image-version source metadata is invalid at {path}: "
                f"{source!r}"
            )
        source_id = source.get("id")
        if source_id not in (None, ""):
            source_ids[f"{path}.id"] = source_id
            if not same(source_id, expected_disk_id):
                raise SystemExit(
                    "gallery image version is not sourced from the exact managed disk: "
                    f"expected {expected_disk_id!r}; observed "
                    f"{json.dumps(source_ids, sort_keys=True)}"
                )
    if not source_ids:
        raise SystemExit(
            "gallery image version does not expose the exact managed disk source: "
            f"expected {expected_disk_id!r}; storageProfile keys "
            f"{sorted(storage)}; osDiskImage keys {sorted(os_disk)}"
        )

    validate_size(
        os_disk,
        "gallery image-version OS disk",
        expected_size_gib,
        ("diskSizeBytes", "sizeInBytes"),
        ("diskSizeGb", "diskSizeGB", "sizeInGB", "sizeInGb"),
        allow_missing=True,
    )
    if storage.get("dataDiskImages") not in (None, []):
        raise SystemExit("gallery image version unexpectedly contains data disks")

    publishing = document.get("publishingProfile")
    if not isinstance(publishing, dict):
        raise SystemExit("gallery image-version publishing profile is missing")
    if publishing.get("replicationMode") != "Shallow":
        raise SystemExit("gallery image-version replication mode mismatch")
    target_regions = publishing.get("targetRegions")
    if not isinstance(target_regions, list) or len(target_regions) != 1:
        raise SystemExit("gallery image-version target region is missing or ambiguous")
    target = target_regions[0]
    if not isinstance(target, dict) or not same_location(target.get("name")):
        raise SystemExit("gallery image-version target location mismatch")
    if target.get("regionalReplicaCount") not in (None, 1):
        raise SystemExit("gallery image-version replica count mismatch")
    if target.get("storageAccountType") not in (None, "Standard_LRS"):
        raise SystemExit("gallery image-version storage account type mismatch")


def validate_vm(argv):
    (
        path,
        expected_id,
        expected_name,
        expected_group,
        expected_location,
        expected_size,
        expected_image_version_id,
        expected_admin,
        expected_architecture,
        expected_size_gib,
    ) = argv
    document = load_document(path)

    if not same(document.get("id"), expected_id):
        raise SystemExit("Azure returned a different VM identity")
    if document.get("name") != expected_name:
        raise SystemExit("Azure returned a different VM name")
    resource_group = document.get("resourceGroup")
    if resource_group not in (None, "") and not same(resource_group, expected_group):
        raise SystemExit("VM is outside the owned temporary resource group")
    if not same(document.get("location"), expected_location):
        raise SystemExit("VM location mismatch")
    if not same(document.get("type"), "Microsoft.Compute/virtualMachines"):
        raise SystemExit("Azure returned a non-VM resource")
    if document.get("provisioningState") != "Succeeded":
        raise SystemExit("VM provisioning did not succeed")
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        document.get("vmId", ""),
    ):
        raise SystemExit("Azure returned an invalid VM instance identity")

    hardware = document.get("hardwareProfile")
    if not isinstance(hardware, dict) or hardware.get("vmSize") != expected_size:
        raise SystemExit("VM size mismatch")
    storage = document.get("storageProfile")
    if not isinstance(storage, dict):
        raise SystemExit("VM storage profile is missing")
    image_reference = storage.get("imageReference")
    if not isinstance(image_reference, dict) or not same(
        image_reference.get("id"), expected_image_version_id
    ):
        raise SystemExit("VM is not bound to the exact gallery image version")
    os_disk = storage.get("osDisk")
    if not isinstance(os_disk, dict):
        raise SystemExit("VM OS disk metadata is missing")
    if os_disk.get("osType") != "Linux" or os_disk.get("createOption") != "FromImage":
        raise SystemExit("VM OS disk was not created as Linux from the image")
    validate_size(
        os_disk,
        "VM OS disk",
        expected_size_gib,
        (
            "diskSizeBytes",
            "sizeInBytes",
            "managedDisk.diskSizeBytes",
            "managedDisk.sizeInBytes",
        ),
        (
            "diskSizeGb",
            "diskSizeGB",
            "sizeInGB",
            "sizeInGb",
            "managedDisk.diskSizeGb",
            "managedDisk.diskSizeGB",
            "managedDisk.sizeInGB",
            "managedDisk.sizeInGb",
        ),
    )
    vm_os_disk_id = (os_disk.get("managedDisk") or {}).get("id")
    disk_prefix = (
        expected_id.rsplit("/providers/", 1)[0]
        + "/providers/Microsoft.Compute/disks/"
    )
    if not isinstance(vm_os_disk_id, str) or not vm_os_disk_id.casefold().startswith(
        disk_prefix.casefold()
    ):
        raise SystemExit("VM OS disk is outside the owned temporary resource group")

    os_profile = document.get("osProfile")
    if (
        not isinstance(os_profile, dict)
        or os_profile.get("adminUsername") != expected_admin
    ):
        raise SystemExit("VM administrator identity mismatch")
    linux = os_profile.get("linuxConfiguration")
    if not isinstance(linux, dict):
        raise SystemExit("VM Linux provisioning policy is missing")
    if linux.get("disablePasswordAuthentication") is not True:
        raise SystemExit("VM does not require key-only authentication")
    if linux.get("provisionVMAgent") is not False:
        raise SystemExit("VM agent policy mismatch")

    security = document.get("securityProfile") or {}
    security_type = security.get("securityType")
    if security_type not in (None, "Standard"):
        raise SystemExit("VM security type mismatch")
    boot = (document.get("diagnosticsProfile") or {}).get("bootDiagnostics") or {}
    if boot.get("enabled") is not True or boot.get("storageUri") not in (None, ""):
        raise SystemExit("VM managed boot diagnostics policy mismatch")
    interfaces = (document.get("networkProfile") or {}).get("networkInterfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 1:
        raise SystemExit("VM network interface metadata is missing or ambiguous")
    nic_prefix = (
        expected_id.rsplit("/providers/", 1)[0]
        + "/providers/Microsoft.Network/networkInterfaces/"
    )
    if not same(interfaces[0].get("id", "")[: len(nic_prefix)], nic_prefix):
        raise SystemExit(
            "VM network interface is outside the owned temporary resource group"
        )

    for owner in (document, hardware, os_disk):
        architecture = owner.get("architecture")
        if architecture not in (None, "") and architecture != expected_architecture:
            raise SystemExit("VM architecture mismatch")
    print(document["id"])


COMMANDS = {
    "managed-disk": (validate_managed_disk, 7),
    "gallery": (validate_gallery, 5),
    "gallery-image-version": (validate_gallery_image_version, 8),
    "vm": (validate_vm, 10),
}


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        raise SystemExit(
            f"usage: {sys.argv[0]} {{{','.join(COMMANDS)}}} VALIDATION_ARGUMENTS..."
        )
    command = argv[0]
    validator, argument_count = COMMANDS[command]
    if len(argv[1:]) != argument_count:
        raise SystemExit(
            f"{command} expects {argument_count} arguments, got {len(argv[1:])}"
        )
    validator(argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
