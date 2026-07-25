import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import types
import unittest
from pathlib import Path

from scripts import azurelinux4_release as release


ROOT = Path(__file__).resolve().parents[1]
TEST_CERTIFICATE_DER = b"zvmi test certificate DER"
TEST_CERTIFICATE_SHA256 = hashlib.sha256(TEST_CERTIFICATE_DER).hexdigest()
TEST_SIGNING_CERTIFICATE_SHA256 = "4" * 64
TEST_SIGNING_OPERATION_ID = "00000000-0000-4000-8000-000000000001"


def fixed_vhd_geometry(virtual_size: int) -> tuple[int, int, int]:
    total_sectors = min(virtual_size // 512, release.VHD_MAX_CHS_SECTORS)
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


def qemu_reported_vhd_size(virtual_size: int) -> int:
    cylinders, heads, sectors_per_track = fixed_vhd_geometry(virtual_size)
    geometry_sectors = cylinders * heads * sectors_per_track
    if geometry_sectors == release.VHD_MAX_CHS_SECTORS:
        return virtual_size
    return geometry_sectors * 512


def fixed_vhd_footer(virtual_size: int, disk_type: int = 2) -> bytes:
    footer = bytearray(release.VHD_FOOTER_BYTES)
    footer[:8] = b"conectix"
    struct.pack_into(">II", footer, 8, 2, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    footer[28:32] = b"zvmi"
    struct.pack_into(">I", footer, 32, 0x00010000)
    struct.pack_into(">QQ", footer, 40, virtual_size, virtual_size)
    struct.pack_into(">HBB", footer, 56, *fixed_vhd_geometry(virtual_size))
    struct.pack_into(">I", footer, 60, disk_type)
    checksum = (~sum(footer)) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


class AzureLinuxReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            Path.cwd()
            / ".scratch"
            / f"azurelinux4-release-test-{os.getpid()}-{self._testMethodName}"
        )
        self.candidates = self.root / "candidates"
        self.azure = self.root / "azure"
        self.source_commit = "a" * 40
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make_bundle(
        self,
        key,
        certificate_der=TEST_CERTIFICATE_DER,
        signing_certificate_sha256=TEST_SIGNING_CERTIFICATE_SHA256,
    ):
        certificate_sha256 = hashlib.sha256(certificate_der).hexdigest()
        architecture, flavor, asset_name = release.EXPECTED[key]
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True)
        asset = candidate_dir / asset_name
        asset.write_bytes((key + "\n").encode())
        provenance = candidate_dir / "internal-provenance"
        provenance.mkdir()
        (provenance / "inputs.txt").write_text(f"{key}\n", encoding="utf-8")
        fallback_path = (
            "EFI/BOOT/BOOTX64.EFI"
            if architecture == "x86_64"
            else "EFI/BOOT/BOOTAA64.EFI"
        )
        signing = {
            "schema": 1,
            "type": "zvmi-uki-signing",
            "architecture": architecture,
            "flavor": flavor,
            "signer_mode": "external-command",
            "certificate_sha256": certificate_sha256,
            "certificate_der_base64": base64.b64encode(certificate_der).decode(),
            "certificate_details": "subject=CN=zvmi test signer",
            "provider": {
                "name": "azure-artifact-signing",
                "endpoint": "https://wus.codesigning.azure.net",
                "account": "cataggar",
                "profile": "zvmi-uki",
                "signing_certificate_sha256": signing_certificate_sha256,
            },
            "signature_verification": "success",
            "files": [
                {
                    "path": f"EFI/Linux/zvmi-{key}.efi",
                    "unsigned_sha256": "2" * 64,
                    "signed_sha256": "3" * 64,
                    "finalized_sha256": "3" * 64,
                    "signed_bytes": 4096,
                    "signing_operation_id": TEST_SIGNING_OPERATION_ID,
                    "signing_certificate_sha256": signing_certificate_sha256,
                },
                {
                    "path": fallback_path,
                    "unsigned_sha256": "2" * 64,
                    "signed_sha256": "3" * 64,
                    "finalized_sha256": "3" * 64,
                    "signed_bytes": 4096,
                    "signing_operation_id": TEST_SIGNING_OPERATION_ID,
                    "signing_certificate_sha256": signing_certificate_sha256,
                },
            ],
        }
        (provenance / f"uki-signing-{flavor}-{architecture}.json").write_text(
            json.dumps(signing), encoding="utf-8"
        )
        digest = release.sha256(asset)
        manifest = candidate_dir / "candidate.json"
        release.candidate_command(
            types.SimpleNamespace(
                key=key,
                architecture=architecture,
                flavor=flavor,
                asset=asset,
                validated_sha256=digest,
                virtual_size=1024,
                source_commit=self.source_commit,
                provenance_dir=provenance,
                runner=f"runner-{architecture}",
                run_id="1",
                run_attempt="1",
                output=manifest,
            )
        )

        azure_dir = self.azure / key
        azure_dir.mkdir(parents=True)
        vhd = azure_dir / "temporary.vhd"
        vhd.write_bytes((key + "-vhd\n").encode())
        uefi_settings = {
            "signatureTemplateNames": [
                "MicrosoftUefiCertificateAuthorityTemplate"
            ],
            "additionalSignatures": {
                "db": [
                    {
                        "type": "x509",
                        "value": [base64.b64encode(certificate_der).decode()],
                    }
                ]
            },
        }
        uefi_request = azure_dir / "uefi-request.json"
        uefi_response = azure_dir / "uefi-response.json"
        payload = {"properties": {"securityProfile": {"uefiSettings": uefi_settings}}}
        uefi_request.write_text(json.dumps(payload), encoding="utf-8")
        uefi_response.write_text(json.dumps(payload), encoding="utf-8")
        release.azure_result_command(
            types.SimpleNamespace(
                manifest=manifest,
                asset=asset,
                vhd=vhd,
                key=key,
                source_commit=self.source_commit,
                location="eastus2",
                vm_size="Standard_D2ds_v5",
                resource_group=f"rg-{key}",
                image_version_id=f"/subscriptions/test/gallery/{key}/versions/1.0.0",
                uefi_request=uefi_request,
                uefi_response=uefi_response,
                run_id="1",
                run_attempt="1",
                output=azure_dir / "azure-result.json",
            )
        )
        vhd.unlink()

    def make_all_bundles(self):
        for key in release.EXPECTED:
            self.make_bundle(key)

    def stage(self):
        output = self.root / "staged"
        notes = self.root / "notes.md"
        release.stage_command(
            types.SimpleNamespace(
                candidates=self.candidates,
                azure_results=self.azure,
                source_commit=self.source_commit,
                release_tag="AzureLinux-4.0-20260723",
                output=output,
                notes=notes,
            )
        )
        return output, notes

    def test_stage_requires_and_copies_exact_four_bound_assets(self):
        self.make_all_bundles()
        output, notes = self.stage()
        manifest = json.loads((output / "publish-manifest.json").read_text())
        self.assertEqual(
            [item["asset_name"] for item in manifest["assets"]],
            [release.EXPECTED[key][2] for key in release.RELEASE_ORDER],
        )
        self.assertEqual(
            sorted(path.name for path in output.glob("*.qcow2")),
            sorted(item[2] for item in release.EXPECTED.values()),
        )
        self.assertEqual(manifest["certificate_sha256"], TEST_CERTIFICATE_SHA256)
        self.assertEqual(
            manifest["signing_certificate_sha256"],
            TEST_SIGNING_CERTIFICATE_SHA256,
        )
        self.assertTrue(
            all(item["fallback_uki_sha256"] == "3" * 64 for item in manifest["assets"])
        )
        self.assertIn("No checksum sidecar assets are published", notes.read_text())

    def test_stage_rejects_absent_azure_matrix_entry(self):
        self.make_all_bundles()
        (self.azure / "aarch64-core" / "azure-result.json").unlink()
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_azure_digest_not_bound_to_candidate(self):
        self.make_all_bundles()
        path = self.azure / "x86_64-full" / "azure-result.json"
        document = json.loads(path.read_text())
        document["azure_accepted_sha256"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_checksum_sidecar(self):
        self.make_all_bundles()
        (self.candidates / "forbidden.sha256").write_text("0" * 64, encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_tampered_internal_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "inputs.txt"
        path.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_missing_signing_provenance(self):
        self.make_all_bundles()
        path = (
            self.candidates
            / "x86_64-full"
            / "internal-provenance"
            / "uki-signing-full-x86_64.json"
        )
        path.unlink()
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_pem_private_key_in_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "inputs.txt"
        path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nsecret\n")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_der_private_key_in_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "inputs.txt"
        path.write_bytes(b"\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_encrypted_der_private_key_in_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "inputs.txt"
        path.write_bytes(
            b"\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00"
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_embedded_der_private_key_in_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "build.log"
        path.write_bytes(
            b"diagnostic output\n"
            b"\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00"
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_pkcs12_private_key_container_in_provenance(self):
        self.make_all_bundles()
        path = self.candidates / "x86_64-full" / "internal-provenance" / "inputs.txt"
        path.write_bytes(b"\x30\x08\x02\x01\x03\x30\x03\x06\x01\x2a")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_mixed_signing_certificates(self):
        for key in release.EXPECTED:
            self.make_bundle(
                key,
                b"different certificate"
                if key == "aarch64-core"
                else TEST_CERTIFICATE_DER,
            )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_mixed_artifact_signing_leaves(self):
        for key in release.EXPECTED:
            self.make_bundle(
                key,
                signing_certificate_sha256=(
                    "5" * 64
                    if key == "aarch64-core"
                    else TEST_SIGNING_CERTIFICATE_SHA256
                ),
            )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_azure_uefi_settings_bind_canonical_der_certificate(self):
        settings = {
            "signatureTemplateNames": [
                "MicrosoftUefiCertificateAuthorityTemplate"
            ],
            "additionalSignatures": {
                "db": [
                    {
                        "type": "x509",
                        "value": [
                            base64.b64encode(TEST_CERTIFICATE_DER).decode()
                        ],
                    }
                ]
            },
        }
        self.assertEqual(
            release.validate_azure_uefi_settings(
                settings, TEST_CERTIFICATE_SHA256
            ),
            settings,
        )
        settings["additionalSignatures"]["db"][0]["value"] = [
            base64.b64encode(b"different").decode()
        ]
        with self.assertRaises(SystemExit):
            release.validate_azure_uefi_settings(
                settings, TEST_CERTIFICATE_SHA256
            )

    def test_azure_gallery_final_get_may_omit_accepted_uefi_settings(self):
        settings = {
            "signatureTemplateNames": [
                "MicrosoftUefiCertificateAuthorityTemplate"
            ],
            "additionalSignatures": {
                "db": [
                    {
                        "type": "x509",
                        "value": [
                            base64.b64encode(TEST_CERTIFICATE_DER).decode()
                        ],
                    }
                ]
            },
        }
        request = {"properties": {"securityProfile": {"uefiSettings": settings}}}
        response = {"properties": {"provisioningState": "Succeeded"}}
        self.assertEqual(
            release.validate_azure_gallery_uefi_settings(
                request,
                response,
                TEST_CERTIFICATE_SHA256,
            ),
            settings,
        )
        response["properties"]["securityProfile"] = {
            "uefiSettings": {"signatureTemplateNames": []}
        }
        with self.assertRaises(SystemExit):
            release.validate_azure_gallery_uefi_settings(
                request,
                response,
                TEST_CERTIFICATE_SHA256,
            )

    def test_fixed_vhd_alignment_applies_to_virtual_size_not_footer(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        file_size = virtual_size + release.VHD_FOOTER_BYTES
        self.assertNotEqual(file_size % release.AZURE_VHD_ALIGNMENT, 0)
        self.assertEqual(
            release.validate_azure_vhd_info(
                info, file_size, fixed_vhd_footer(virtual_size)
            ),
            virtual_size,
        )

    def test_fixed_vhd_rejects_unaligned_virtual_size(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT + 512
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info,
                virtual_size + release.VHD_FOOTER_BYTES,
                fixed_vhd_footer(virtual_size),
            )

    def test_fixed_vhd_requires_exact_footer_relationship(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info, virtual_size, fixed_vhd_footer(virtual_size)
            )

    def test_fixed_vhd_rejects_non_vpc_format(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "raw",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info,
                virtual_size + release.VHD_FOOTER_BYTES,
                fixed_vhd_footer(virtual_size),
            )

    def test_fixed_vhd_rejects_dynamic_footer(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info,
                virtual_size + release.VHD_FOOTER_BYTES,
                fixed_vhd_footer(virtual_size, disk_type=3),
            )

    def test_fixed_vhd_rejects_corrupt_footer_checksum(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        footer = bytearray(fixed_vhd_footer(virtual_size))
        footer[100] ^= 0xFF
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info,
                virtual_size + release.VHD_FOOTER_BYTES,
                bytes(footer),
            )

    def test_fixed_vhd_rejects_inconsistent_chs_geometry(self):
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        info = {
            "format": "vpc",
            "virtual-size": qemu_reported_vhd_size(virtual_size),
        }
        footer = bytearray(fixed_vhd_footer(virtual_size))
        cylinders = struct.unpack_from(">H", footer, 56)[0]
        struct.pack_into(">H", footer, 56, cylinders - 1)
        footer[64:68] = b"\0" * 4
        struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
        with self.assertRaises(SystemExit):
            release.validate_azure_vhd_info(
                info,
                virtual_size + release.VHD_FOOTER_BYTES,
                bytes(footer),
            )

    def test_release_artifacts_use_visible_attempt_bound_staging(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        staging = dict(
            (name, value.strip())
            for name, value in re.findall(
                r"^[ \t]+(BUNDLE_DIR|RESULT_DIR):[ \t]+([^\n]+)$",
                workflow,
                re.MULTILINE,
            )
        )
        self.assertEqual(set(staging), {"BUNDLE_DIR", "RESULT_DIR"})
        for path in staging.values():
            self.assertFalse(any(part.startswith(".") for part in Path(path).parts))

        artifact_references = [
            line.strip()
            for line in workflow.splitlines()
            if re.match(r"\s+(name|pattern): azurelinux4-(candidate|azure)-", line)
        ]
        self.assertEqual(len(artifact_references), 6)
        for reference in artifact_references:
            self.assertIn("${{ needs.prepare.outputs.source_commit }}", reference)
        candidate_references = [
            reference
            for reference in artifact_references
            if "azurelinux4-candidate-" in reference
        ]
        self.assertEqual(len(candidate_references), 3)
        for reference in candidate_references:
            if "${{ matrix.key }}" not in reference:
                self.assertIn(
                    "${{ needs.prepare.outputs.candidate_run_attempt }}",
                    reference,
                )
        azure_references = [
            reference
            for reference in artifact_references
            if "azurelinux4-azure-" in reference
        ]
        self.assertEqual(len(azure_references), 3)
        for reference in azure_references:
            self.assertIn("${{ github.run_attempt }}", reference)

    def test_release_reuse_is_bound_to_completed_candidates(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        self.assertIn("candidate_run_id:", workflow)
        self.assertIn('test "$(jq -r .status <<<"$run")" = completed', workflow)
        self.assertIn('.conclusion == "success"', workflow)
        self.assertIn(".expired == false", workflow)
        self.assertIn(
            'test "$(git ls-remote origin "refs/tags/$RELEASE_TAG"',
            workflow,
        )
        self.assertEqual(
            workflow.count("run-id: ${{ needs.prepare.outputs.candidate_run_id }}"),
            2,
        )

    def test_azure_acceptance_uses_protected_environment_oidc(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        acceptance = workflow.split("  azure_acceptance:", 1)[1].split(
            "\n  publish:", 1
        )[0]
        self.assertIn("id-token: write", acceptance)
        self.assertEqual(
            acceptance.count("client-id: ${{ secrets.AZURE_CLIENT_ID }}"),
            2,
        )
        self.assertEqual(
            acceptance.count("tenant-id: ${{ secrets.AZURE_TENANT_ID }}"),
            2,
        )
        self.assertEqual(
            acceptance.count(
                "subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}"
            ),
            2,
        )
        self.assertNotIn("clientSecret", acceptance)
        self.assertNotIn("AZURE_CLIENT_SECRET", acceptance)
        self.assertIn("Upload failed Azure acceptance diagnostics", acceptance)
        self.assertNotIn("AZURE_CORE_OUTPUT", acceptance)

        script = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        self.assertIn("set -Eeuo pipefail", script)
        self.assertIn("Azure acceptance failed at line", script)
        self.assertIn("guest acceptance failed at line", script)
        self.assertIn("sshd_config=$(sudo -n /usr/sbin/sshd -T)", script)
        self.assertNotIn("/usr/sbin/sshd -T | grep", script)
        self.assertIn("az vm boot-diagnostics get-boot-log", script)
        self.assertNotIn("az disk grant-access", script)
        self.assertIn("/beginGetAccess?api-version=2025-01-02", script)
        self.assertIn('tolower($1) == "location"', script)
        self.assertIn('response.get("accessSAS")', script)
        self.assertGreaterEqual(script.count("--output json >/dev/null"), 9)
        self.assertIn("gallery-version-create-response.json", script)
        self.assertIn("Azure did not accept the exact custom UEFI settings", script)
        self.assertIn("if actual is not None and actual != expected:", script)
        self.assertIn("boot validation remains authoritative", script)

    def test_azure_acceptance_uses_current_harness_with_accepted_source_tool(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        acceptance = workflow.split("  azure_acceptance:", 1)[1].split(
            "\n  publish:", 1
        )[0]
        self.assertIn("name: Check out acceptance harness", acceptance)
        self.assertIn("ref: ${{ github.sha }}", acceptance)
        self.assertIn("path: release-source", acceptance)
        self.assertIn("working-directory: release-source", acceptance)
        self.assertIn(
            '--build-file "$GITHUB_WORKSPACE/vendor/zig-bzip2/build.zig"',
            acceptance,
        )
        self.assertIn(
            "ZVMI: ${{ github.workspace }}/release-source/zig-out/bin/zvmi",
            acceptance,
        )
        bzip2_manifest = (ROOT / "vendor/zig-bzip2/build.zig.zon").read_text()
        self.assertIn(
            "https://mirrors.kernel.org/sourceware/bzip2/bzip2-1.0.8.tar.gz",
            bzip2_manifest,
        )
        self.assertIn(
            "N-V-__8AAEg_LwBxlEVzMYnlhoZahVvdwk6ddIRturUKBCXF",
            bzip2_manifest,
        )

    def test_azure_acceptance_allows_arm64_without_temporary_resource_disk(self):
        script = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        self.assertIn('restriction.get("type") == "Location"', script)
        self.assertIn('capabilities.get("TrustedLaunchDisabled") == "True"', script)
        self.assertIn('if sys.argv[3] == "x64" and not has_resource_disk:', script)
        self.assertIn("if mountpoint -q /d; then", script)
        self.assertIn('test "$has_resource_disk" = false', script)

    def test_azure_acceptance_identifies_attached_data_disk_by_exact_size(self):
        script = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        self.assertIn("data_disk_size_gib=4", script)
        self.assertIn("expected_data_disk_size=$((data_disk_size_gib * 1073741824))", script)
        self.assertIn('blockdev --getsize64 "/dev/$name"', script)
        self.assertIn('"$size" -eq "$expected_size"', script)
        self.assertNotIn('test -z "${first_sector//0/}"', script)
        self.assertNotIn("/usr/sbin/mkfs.ext4", script)
        self.assertNotIn("/usr/sbin/partprobe", script)
        self.assertNotIn("MSFT NVMe Accelerator", script)
        self.assertIn("Azure managed boot diagnostics did not return a serial log", script)
        self.assertIn(
            '[[ -n "$boot_id" && "$boot_id" != "$old_boot_id" ]]',
            script,
        )
        self.assertNotIn("saw_disconnect", script)

    def test_fixed_vhd_uses_supported_structural_validation(self):
        script = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        self.assertNotIn("qemu-img check -f vpc", script)
        self.assertIn('qemu-img info -f vpc --output=json "$vhd"', script)
        self.assertIn("azurelinux4_release.py verify-vhd", script)

    def test_publisher_verifies_drafts_by_release_id(self):
        script = (ROOT / "scripts/azurelinux4_publish.sh").read_text()
        self.assertIn("--json databaseId", script)
        self.assertIn('release_api="repos/$REPOSITORY/releases/$release_id"', script)
        self.assertEqual(script.count('gh api "$release_api"'), 3)
        self.assertNotIn("releases/tags/$RELEASE_TAG", script)

    def test_ci_actions_are_pinned_to_audited_commits(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        actions = re.findall(
            r"^[ \t]*-?[ \t]*uses:[ \t]+(\S+)[ \t]+#[ \t]+(\S+)$",
            workflow,
            re.MULTILINE,
        )
        self.assertEqual(
            actions,
            [
                (
                    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                    "v4",
                ),
                (
                    "cataggar/ghr/actions/install@"
                    "7d8c3ef0886dd428a97727fce3b74909d6eace78",
                    "v0.6.6",
                ),
            ],
        )
        for action, _ in actions:
            self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_release_workflow_uses_hosted_architecture_runners(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        invocation = 'scripts/check_azurelinux4_release_runner.sh "$ARCHITECTURE"'
        self.assertNotIn(invocation, workflow)
        self.assertNotIn("self-hosted", workflow)
        self.assertEqual(workflow.count("runner: ubuntu-24.04\n"), 2)
        self.assertEqual(workflow.count("runner: ubuntu-24.04-arm\n"), 2)
        self.assertIn("max-parallel: 2", workflow)
        self.assertNotIn("test-azurelinux4-acceptance", workflow)
        self.assertIn("scripts/azurelinux4_azure_acceptance.sh run", workflow)

    def test_candidate_records_build_validation_not_local_kvm_acceptance(self):
        self.make_bundle("x86_64-full")
        document = json.loads(
            (self.candidates / "x86_64-full" / "candidate.json").read_text()
        )
        self.assertEqual(document["build_validation"]["status"], "success")
        self.assertNotIn("local_acceptance", document)

    def test_release_workflow_requires_built_in_signing_and_secure_boot(self):
        workflow = (ROOT / ".github/workflows/azurelinux4-release.yml").read_text()
        self.assertIn("environment: azurelinux4-signing", workflow)
        self.assertNotIn("AZURELINUX4_UKI_SIGN_COMMAND", workflow)
        self.assertIn(
            "UKI_SIGN_COMMAND: ${{ github.workspace }}/zig-out/bin/zvmi",
            workflow,
        )
        self.assertIn("zig build install-zvmi", workflow)
        self.assertIn("tests/efi_signing_probe.zig", workflow)
        self.assertIn('"$UKI_SIGN_COMMAND" sign', workflow)
        self.assertIn(
            'sbverify --verbose --cert "$UKI_SIGNING_CERTIFICATE" "$signed"',
            workflow,
        )
        self.assertIn("Upload failed signing probe", workflow)
        self.assertIn(
            "SIGNING_PROBE_DIR: ${{ github.workspace }}/signing-probe-",
            workflow,
        )
        self.assertNotIn("/.signing-probe-", workflow)
        self.assertIn("--uki-sign-command \"$UKI_SIGN_COMMAND\"", workflow)
        self.assertIn("--uki-sign-command-arg sign", workflow)
        self.assertIn("ZVMI_AZURE_TENANT_ID", workflow)
        self.assertIn("ZVMI_AZURE_CLIENT_ID", workflow)
        self.assertIn("ZVMI_ARTIFACT_SIGNING_ENDPOINT", workflow)
        self.assertIn("ZVMI_ARTIFACT_SIGNING_ACCOUNT", workflow)
        self.assertIn("ZVMI_ARTIFACT_SIGNING_PROFILE", workflow)
        self.assertNotIn("ZVMI_AZURE_KEY_ID", workflow)
        self.assertNotIn("--uki-signing-key", workflow)
        self.assertIn("python3-virt-firmware", workflow)
        self.assertIn("sbsigntool", workflow)

        azure = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        self.assertIn("api-version=2025-03-03", azure)
        self.assertIn("MicrosoftUefiCertificateAuthorityTemplate", azure)
        self.assertIn("--security-type TrustedLaunch", azure)
        self.assertIn("--enable-secure-boot true", azure)
        self.assertIn("--enable-vtpm true", azure)

    def test_runner_probe_help_and_invalid_architecture(self):
        script = ROOT / "scripts/check_azurelinux4_release_runner.sh"
        subprocess.run(["bash", script, "--help"], check=True, capture_output=True)
        result = subprocess.run(
            ["bash", script, "riscv64"], check=False, capture_output=True
        )
        self.assertEqual(result.returncode, 2)
        text = script.read_text()
        self.assertIn("timeout --signal=TERM --kill-after=2s 2s", text)
        self.assertNotIn("-daemonize", text)
        self.assertNotIn("-pidfile", text)

    def test_resource_group_state_precedes_create_and_cleanup_is_guarded(self):
        script = (ROOT / "scripts/azurelinux4_azure_acceptance.sh").read_text()
        persist = script.index("printf '%s\\n' \"$resource_group\" >\"$STATE_FILE\"")
        create = script.index("if ! az group create")
        self.assertLess(persist, create)
        self.assertIn('[[ "$resource_group" == "$expected_resource_group" ]]', script)
        ownership_guard = script.index("if ! python3 - \"$metadata_file\"")
        delete = script.index("if ! az group delete")
        self.assertLess(ownership_guard, delete)

    def test_qemu_guide_distinguishes_default_full_and_core_output(self):
        guide = (ROOT / "doc/qemu.md").read_text()
        section = guide.split("## Booting the release image with QEMU", 1)[1]
        self.assertIn("full image's systemd startup and login prompt", section)
        self.assertIn(
            "only when a core image is selected with `--model core` or\n"
            "an explicit `*.core.qcow2` path",
            section,
        )
        self.assertNotIn(
            "default secure command line, a successful local boot reaches\n"
            "the PID 1 readiness marker",
            section,
        )

    def test_azure_linux_guide_distinguishes_full_and_core_images(self):
        guide = (ROOT / "doc/azure-linux.md").read_text()
        self.assertIn("| PID 1 | systemd | `zvminit` |", guide)
        self.assertIn("| Default virtual size | 5 GiB | 1184 MiB |", guide)
        self.assertIn(
            "released Azure core images use `zvminit.mode=persistent`",
            guide,
        )
        self.assertIn(
            "| Azure extensions | Standard WALinuxAgent extension support | "
            "No general WALinuxAgent extension stack |",
            guide,
        )

    def test_root_readme_is_a_short_documentation_landing_page(self):
        readme = (ROOT / "README.md").read_text()
        headings = [line for line in readme.splitlines() if line.startswith("#")]
        self.assertEqual(headings, ["# zvmi", "## Install", "## Documentation"])
        self.assertLess(len(readme.splitlines()), 60)
        self.assertIn("[Documentation index](doc/readme.md)", readme)

    def test_cli_release_packages_documentation(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("test -f doc/readme.md", workflow)
        self.assertIn('cp -R doc "$package/"', workflow)


if __name__ == "__main__":
    unittest.main()
