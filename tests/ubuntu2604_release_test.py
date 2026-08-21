import base64
import hashlib
import json
import os
import re
import shutil
import struct
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts import ubuntu2604_release as release


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_DER = b"vmiz Ubuntu test certificate"
CERTIFICATE_SHA256 = hashlib.sha256(CERTIFICATE_DER).hexdigest()
SIGNING_CERTIFICATE_SHA256 = "4" * 64
OPERATION_ID = "00000000-0000-4000-8000-000000000001"
FORBIDDEN_PRODUCTION_TOOL = re.compile(
    r"libguestfs|guestfish|supermin|LIBGUESTFS_BACKEND_SETTINGS|"
    r"\bvirt-(?!fw-vars\b|firmware\b)[a-z0-9-]+"
)


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


def fixed_vhd_footer(virtual_size: int) -> bytes:
    footer = bytearray(release.VHD_FOOTER_BYTES)
    footer[:8] = b"conectix"
    struct.pack_into(">II", footer, 8, 2, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    footer[28:32] = b"vmiz"
    struct.pack_into(">I", footer, 32, 0x00010000)
    struct.pack_into(">QQ", footer, 40, virtual_size, virtual_size)
    struct.pack_into(">HBB", footer, 56, *fixed_vhd_geometry(virtual_size))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


class Ubuntu2604ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            Path.cwd()
            / ".scratch"
            / f"ubuntu2604-release-{os.getpid()}-{self._testMethodName}"
        )
        self.candidates = self.root / "candidates"
        self.azure = self.root / "azure"
        self.source_commit = "a" * 40
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_package_root_uses_native_mountless_ext4_round_trip(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        production = builder.split('test "profiles pin', 1)[0]
        self.assertIn(
            "vmiz.ext4_mountless.FileSystem.open",
            production,
        )
        self.assertIn("exportHostTree", production)
        self.assertIn("importHostTree", production)
        self.assertIn("native_root.finish()", production)
        self.assertIn("cloudimg-rootfs", production)
        self.assertNotIn("/dev/sda4", production)
        self.assertNotIn("/dev/sda3", production)
        for forbidden in (
            "virt-tar-out",
            "virt-tar-in",
            '"guestfish"',
            '"tar"',
            '"cp"',
        ):
            self.assertNotIn(forbidden, production)

    def test_production_builder_has_only_documented_qemu_img_boundary(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        production = builder.split('test "profiles pin', 1)[0]
        self.assertIsNone(FORBIDDEN_PRODUCTION_TOOL.search(production))
        self.assertEqual(production.count('"qemu-img"'), 2)
        self.assertIn(
            '"qemu-img", "convert"',
            production,
        )
        self.assertIn(
            "sole external image-format",
            production,
        )

    def make_bundle(
        self,
        key: str,
        *,
        certificate_der: bytes = CERTIFICATE_DER,
        signing_certificate_sha256: str = SIGNING_CERTIFICATE_SHA256,
    ) -> None:
        architecture, flavor, asset_name = release.EXPECTED[key]
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True)
        asset = candidate_dir / asset_name
        asset.write_bytes((key + "\n").encode())
        provenance = candidate_dir / "internal-provenance"
        provenance.mkdir()
        source_architecture = "amd64" if architecture == "x86_64" else "arm64"
        prefix = f"ubuntu-26.04-server-cloudimg-{source_architecture}"
        artifact_digests = {
            "source_image": "5" * 64,
        }
        artifact_filenames = {
            "source_image": f"{prefix}.img",
            "image_manifest": f"{prefix}.manifest",
        }
        for name in ("image_manifest",):
            path = provenance / artifact_filenames[name]
            path.write_text(f"{name} for {key}\n", encoding="utf-8")
            artifact_digests[name] = release.sha256(path)
        checksum_lines = [
            f"{artifact_digests[name]}  {artifact_filenames[name]}"
            for name in artifact_filenames
        ]
        checksum_path = provenance / "SHA256SUMS"
        checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        signature_path = provenance / "SHA256SUMS.gpg"
        signature_path.write_bytes(b"detached signature")

        debz_transactions = []
        for index, package in enumerate(release.DEBZ_PACKAGES):
            lock_digest = str(7 + index) * 64
            lock_path = (
                provenance
                / f"debz-exact-lock-{package}-{source_architecture}.json"
            )
            lock_path.write_text(
                json.dumps(
                    {
                        "schema": (
                            "https://debz.dev/schema/exact-closure-lock-v1"
                        ),
                        "version": 1,
                        "target_architecture": source_architecture,
                        "request_sha256": "1" * 64,
                        "policy_sha256": "2" * 64,
                        "repositories": [{"fixture": True}],
                        "packages": [
                            {
                                "name": "base-files",
                                "version": "1",
                                "architecture": source_architecture,
                                "retention": "retained",
                            },
                            {
                                "name": package,
                                "version": "1",
                                "architecture": source_architecture,
                                "retention": "requested",
                            },
                        ],
                        "digest_sha256": lock_digest,
                    }
                ),
                encoding="utf-8",
            )
            transaction_digest = chr(ord("a") + index) * 64
            transaction_path = (
                provenance
                / (
                    "debz-transaction-provenance-"
                    f"{package}-{source_architecture}.json"
                )
            )
            transaction_path.write_text(
                json.dumps(
                    {
                        "schema": (
                            "https://debz.dev/schema/transaction-result-v1"
                        ),
                        "version": 1,
                        "target_architecture": source_architecture,
                        "lock_sha256": lock_digest,
                        "outcome": "succeeded",
                        "final_verification": {"status": "exact_match"},
                        "digest_sha256": transaction_digest,
                    }
                ),
                encoding="utf-8",
            )
            debz_transactions.append(
                {
                    "package": package,
                    "exact_lock": {
                        "filename": lock_path.name,
                        "sha256": release.sha256(lock_path),
                        "digest_sha256": lock_digest,
                    },
                    "transaction_provenance": {
                        "filename": transaction_path.name,
                        "sha256": release.sha256(transaction_path),
                        "digest_sha256": transaction_digest,
                        "lock_sha256": lock_digest,
                    },
                }
            )
        provenance_document = {
            "schema": 1,
            "type": "vmiz-ubuntu2604-build-provenance",
            "architecture": architecture,
            "release": "26.04",
            "snapshot": {
                "id": "release-20260731",
                "base_url": (
                    "https://cloud-images.ubuntu.com/releases/"
                    "26.04/release-20260731/"
                ),
            },
            "canonical_key_fingerprint": "c" * 40,
            "sha256sums_signature_verified": True,
            "artifacts": {
                "sha256sums": {
                    "filename": "SHA256SUMS",
                    "sha256": release.sha256(checksum_path),
                },
                "sha256sums_signature": {
                    "filename": "SHA256SUMS.gpg",
                    "sha256": release.sha256(signature_path),
                },
                **{
                    name: {
                        "filename": filename,
                        "sha256": artifact_digests[name],
                    }
                    for name, filename in artifact_filenames.items()
                },
            },
            "debz": {
                "api_commit": release.DEBZ_API_COMMIT,
                "baseline": {
                    "source": "canonical-image-dpkg-status",
                    "enforcement": "exact-final-closure",
                },
                "transactions": debz_transactions,
            },
        }
        (provenance / release.UBUNTU_PROVENANCE_FILENAME).write_text(
            json.dumps(provenance_document), encoding="utf-8"
        )
        certificate_sha256 = hashlib.sha256(certificate_der).hexdigest()
        fallback = (
            "EFI/BOOT/BOOTX64.EFI"
            if architecture == "x86_64"
            else "EFI/BOOT/BOOTAA64.EFI"
        )
        signing = {
            "schema": 1,
            "type": "vmiz-uki-signing",
            "architecture": architecture,
            "flavor": flavor,
            "signer_mode": "external-command",
            "certificate_sha256": certificate_sha256,
            "certificate_der_base64": base64.b64encode(certificate_der).decode(),
            "certificate_details": "subject=CN=vmiz Ubuntu test signer",
            "provider": {
                "name": "azure-artifact-signing",
                "endpoint": "https://wus.codesigning.azure.net",
                "account": "cataggar",
                "profile": "vmiz-uki",
                "signing_certificate_sha256": signing_certificate_sha256,
            },
            "signature_verification": "success",
            "files": [
                {
                    "path": f"EFI/Linux/vmiz-{key}.efi",
                    "unsigned_sha256": "2" * 64,
                    "signed_sha256": "3" * 64,
                    "finalized_sha256": "3" * 64,
                    "signed_bytes": 4096,
                    "signing_operation_id": OPERATION_ID,
                    "signing_certificate_sha256": signing_certificate_sha256,
                },
                {
                    "path": fallback,
                    "unsigned_sha256": "2" * 64,
                    "signed_sha256": "3" * 64,
                    "finalized_sha256": "3" * 64,
                    "signed_bytes": 4096,
                    "signing_operation_id": OPERATION_ID,
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
                virtual_size=2 * release.AZURE_VHD_ALIGNMENT,
                source_commit=self.source_commit,
                provenance_dir=provenance,
                runner=f"ubuntu-{architecture}",
                run_id="100",
                run_attempt="1",
                output=manifest,
            )
        )

        azure_dir = self.azure / key
        azure_dir.mkdir(parents=True)
        vhd = azure_dir / "temporary.vhd"
        current_size = 2 * release.AZURE_VHD_ALIGNMENT
        with vhd.open("wb") as stream:
            stream.seek(current_size)
            stream.write(fixed_vhd_footer(current_size))
        vhd_info = azure_dir / "vhd-info.json"
        vhd_info.write_text(
            json.dumps({"format": "vpc", "virtual-size": current_size}),
            encoding="utf-8",
        )
        conversion = azure_dir / "conversion-attestation.json"
        conversion.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "type": "vmiz-azure-vhd-conversion",
                    "key": key,
                    "status": "success",
                    "tool": "vmiz",
                    "operation": "azure derive",
                    "source": {
                        "asset_name": asset_name,
                        "sha256_before": digest,
                        "sha256_after": digest,
                        "bytes": asset.stat().st_size,
                        "virtual_size": current_size,
                    },
                    "parameters": {
                        "input_sha256": digest,
                        "expected_virtual_size": current_size,
                        "output_format": "vpc-fixed",
                        "vhd_alignment_bytes": release.AZURE_VHD_ALIGNMENT,
                        "vhd_footer_bytes": release.VHD_FOOTER_BYTES,
                    },
                    "result": {
                        "sha256": release.sha256(vhd),
                        "bytes": vhd.stat().st_size,
                        "current_size": current_size,
                        "qemu_virtual_size": current_size,
                        "qemu_info_sha256": release.sha256(vhd_info),
                    },
                }
            ),
            encoding="utf-8",
        )
        settings = {
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
        request = azure_dir / "request.json"
        response = azure_dir / "response.json"
        gallery = {"properties": {"securityProfile": {"uefiSettings": settings}}}
        request.write_text(json.dumps(gallery), encoding="utf-8")
        response.write_text(json.dumps(gallery), encoding="utf-8")
        release.azure_result_command(self.azure_result_args(key))

    def azure_result_args(self, key: str):
        _, _, asset_name = release.EXPECTED[key]
        candidate_dir = self.candidates / key
        azure_dir = self.azure / key
        return types.SimpleNamespace(
            manifest=candidate_dir / "candidate.json",
            asset=candidate_dir / asset_name,
            vhd=azure_dir / "temporary.vhd",
            vhd_info=azure_dir / "vhd-info.json",
            conversion_attestation=azure_dir / "conversion-attestation.json",
            key=key,
            source_commit=self.source_commit,
            location="eastus2",
            vm_size="Standard_D2ds_v5",
            resource_group=f"ubuntu-{key}",
            image_version_id=(
                f"/subscriptions/test/gallery/ubuntu/{key}/versions/1.0.0"
            ),
            uefi_request=azure_dir / "request.json",
            uefi_response=azure_dir / "response.json",
            run_id="100",
            run_attempt="1",
            output=azure_dir / "azure-result.json",
        )

    def make_all(self) -> None:
        for key in release.EXPECTED:
            self.make_bundle(key)

    def stage(self, release_tag: str = "Ubuntu-26.04-20260826"):
        output = self.root / "staged"
        notes = self.root / "release-notes.md"
        release.stage_command(
            types.SimpleNamespace(
                candidates=self.candidates,
                azure_results=self.azure,
                source_commit=self.source_commit,
                release_tag=release_tag,
                output=output,
                notes=notes,
            )
        )
        return output, notes

    def rewrite(self, path: Path, mutate) -> None:
        document = json.loads(path.read_text())
        mutate(document)
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_success_stages_exact_two_assets_and_release_metadata(self):
        self.make_all()
        output, notes = self.stage()
        manifest = json.loads((output / "publish-manifest.json").read_text())
        self.assertEqual(manifest["type"], "vmiz-ubuntu2604-release")
        self.assertEqual(manifest["source_commit"], self.source_commit)
        self.assertEqual(manifest["certificate_sha256"], CERTIFICATE_SHA256)
        self.assertEqual(
            manifest["signing_certificate_sha256"],
            SIGNING_CERTIFICATE_SHA256,
        )
        self.assertEqual(
            [asset["asset_name"] for asset in manifest["assets"]],
            [release.EXPECTED[key][2] for key in release.RELEASE_ORDER],
        )
        self.assertEqual(
            {path.name for path in output.glob("*.qcow2")},
            {value[2] for value in release.EXPECTED.values()},
        )
        text = notes.read_text()
        self.assertIn("Ubuntu Server 26.04", text)
        self.assertIn("No checksum sidecar assets are published", text)
        self.assertNotIn("core", text.lower())

    def test_candidate_and_azure_result_schemas_bind_published_bytes(self):
        self.make_bundle("x86_64-full")
        candidate = json.loads(
            (self.candidates / "x86_64-full" / "candidate.json").read_text()
        )
        azure = json.loads(
            (self.azure / "x86_64-full" / "azure-result.json").read_text()
        )
        self.assertEqual(candidate["type"], "ubuntu2604-candidate")
        self.assertEqual(azure["type"], "ubuntu2604-azure-acceptance")
        self.assertEqual(azure["qcow_sha256"], candidate["sha256"])
        self.assertEqual(azure["azure_accepted_sha256"], candidate["sha256"])
        self.assertEqual(
            azure["conversion"]["source"]["sha256_before"],
            candidate["sha256"],
        )
        self.assertEqual(
            azure["conversion"]["parameters"]["expected_virtual_size"],
            candidate["virtual_size"],
        )
        self.assertEqual(set(azure["contracts"]), release.AZURE_CONTRACTS)

    def test_candidate_rejects_validation_digest_mismatch(self):
        key = "x86_64-full"
        architecture, flavor, asset_name = release.EXPECTED[key]
        self.make_bundle(key)
        root = self.candidates / key
        with self.assertRaises(SystemExit):
            release.candidate_command(
                types.SimpleNamespace(
                    key=key,
                    architecture=architecture,
                    flavor=flavor,
                    asset=root / asset_name,
                    validated_sha256="0" * 64,
                    virtual_size=2 * release.AZURE_VHD_ALIGNMENT,
                    source_commit=self.source_commit,
                    provenance_dir=root / "internal-provenance",
                    runner="runner",
                    run_id="1",
                    run_attempt="1",
                    output=root / "rejected-candidate.json",
                )
            )

    def test_verify_rejects_tampered_candidate_bytes_and_size(self):
        self.make_bundle("x86_64-full")
        bundle = self.candidates / "x86_64-full"
        asset = bundle / release.EXPECTED["x86_64-full"][2]
        asset.write_bytes(b"tampered")
        with self.assertRaises(SystemExit):
            release.verify_candidate(bundle / "candidate.json", asset)

    def test_stage_rejects_missing_or_extra_candidate_documents(self):
        self.make_all()
        (self.candidates / "aarch64-full" / "candidate.json").unlink()
        with self.assertRaises(SystemExit):
            self.stage()
        shutil.rmtree(self.root / "staged", ignore_errors=True)
        self.make_bundle_after_reset("aarch64-full")
        extra = self.candidates / "unexpected"
        extra.mkdir()
        shutil.copy(
            self.candidates / "x86_64-full" / "candidate.json",
            extra / "candidate.json",
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_requires_exact_two_azure_results(self):
        self.make_all()
        (self.azure / "aarch64-full" / "azure-result.json").unlink()
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_extra_qcow_and_checksum_sidecar(self):
        self.make_all()
        (self.candidates / "extra.qcow2").write_bytes(b"extra")
        with self.assertRaises(SystemExit):
            self.stage()
        (self.candidates / "extra.qcow2").unlink()
        (self.azure / "forbidden.sha256").write_text("0" * 64)
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_source_commit_and_identity_changes(self):
        self.make_all()
        path = self.candidates / "x86_64-full" / "candidate.json"
        self.rewrite(path, lambda value: value.__setitem__("source_commit", "b" * 40))
        with self.assertRaises(SystemExit):
            self.stage()
        self.rewrite(path, lambda value: value.__setitem__("source_commit", self.source_commit))
        self.rewrite(path, lambda value: value.__setitem__("asset_name", "other.qcow2"))
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_tampered_or_unbound_provenance(self):
        self.make_all()
        provenance = self.candidates / "x86_64-full" / "internal-provenance"
        (provenance / "ubuntu-26.04-server-cloudimg-amd64.manifest").write_text(
            "tampered", encoding="utf-8"
        )
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        (provenance / "unbound.log").write_text("new", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_ubuntu_provenance_requires_immutable_signed_snapshot_inputs(self):
        mutations = (
            lambda value: value["snapshot"].__setitem__(
                "base_url",
                "https://cloud-images.ubuntu.com/releases/26.04/current/",
            ),
            lambda value: value.__setitem__(
                "canonical_key_fingerprint", "not-a-fingerprint"
            ),
            lambda value: value.__setitem__(
                "sha256sums_signature_verified", False
            ),
            lambda value: value["artifacts"].pop("source_image"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_bundle("x86_64-full")
                root = (
                    self.candidates
                    / "x86_64-full"
                    / "internal-provenance"
                )
                path = root / release.UBUNTU_PROVENANCE_FILENAME
                self.rewrite(path, mutate)
                with self.assertRaises(SystemExit):
                    release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_binds_source_and_manifest_checksums(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        checksum = root / "SHA256SUMS"
        checksum.write_text(
            "\n".join(checksum.read_text().splitlines()[:-1]) + "\n",
            encoding="utf-8",
        )
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["artifacts"]["sha256sums"].__setitem__(
                "sha256", release.sha256(checksum)
            ),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_binds_debz_lock_and_transaction(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["transactions"][0][
                "transaction_provenance"
            ].__setitem__("lock_sha256", "0" * 64),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_requires_locked_baseline_for_both_architectures(self):
        for key, architecture in (
            ("x86_64-full", "x86_64"),
            ("aarch64-full", "aarch64"),
        ):
            with self.subTest(architecture=architecture):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_bundle(key)
                root = self.candidates / key / "internal-provenance"
                metadata = root / release.UBUNTU_PROVENANCE_FILENAME
                document = json.loads(metadata.read_text(encoding="utf-8"))
                transaction = document["debz"]["transactions"][0]
                lock_path = root / transaction["exact_lock"]["filename"]
                lock = json.loads(lock_path.read_text(encoding="utf-8"))
                lock["packages"] = [
                    entry
                    for entry in lock["packages"]
                    if entry.get("retention") != "retained"
                ]
                lock_path.write_text(json.dumps(lock), encoding="utf-8")
                transaction["exact_lock"]["sha256"] = release.sha256(lock_path)
                metadata.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    release.validate_ubuntu_provenance(root, architecture)

    def test_ubuntu_provenance_requires_explicit_baseline_contract(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["baseline"].__setitem__(
                "enforcement", "transaction-actions-only"
            ),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_requires_two_stably_ordered_debz_transactions(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["transactions"].reverse(),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def make_bundle_after_reset(self, key: str) -> None:
        shutil.rmtree(self.candidates / key)
        shutil.rmtree(self.azure / key)
        self.make_bundle(key)

    def test_stage_rejects_pem_der_and_embedded_private_keys(self):
        payloads = (
            b"-----BEGIN PRIVATE KEY-----\nsecret\n",
            b"-----BEGIN DSA PRIVATE KEY-----\nsecret\n",
            b"\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00",
            b"prefix\n\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
            b"binary-prefix\0openssh-key-v1\0binary-private-key",
        )
        for index, payload in enumerate(payloads):
            with self.subTest(index=index):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_all()
                path = (
                    self.candidates
                    / "x86_64-full"
                    / "internal-provenance"
                    / "ubuntu-26.04-server-cloudimg-amd64.manifest"
                )
                path.write_bytes(payload)
                with self.assertRaises(SystemExit):
                    self.stage()

    def test_stage_rejects_acceptance_digest_and_contract_changes(self):
        self.make_all()
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("azure_accepted_sha256", "0" * 64))
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        self.rewrite(path, lambda value: value["contracts"].pop())
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_acceptance_status_and_vhd_evidence_changes(self):
        self.make_all()
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("status", "failure"))
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        self.rewrite(
            path,
            lambda value: value["conversion"]["result"].__setitem__(
                "current_size",
                value["conversion"]["result"]["current_size"]
                + release.AZURE_VHD_ALIGNMENT,
            )
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_azure_result_rejects_malformed_vhd_structure(self):
        self.make_bundle("x86_64-full")
        vhd = self.azure / "x86_64-full" / "temporary.vhd"
        with vhd.open("r+b") as stream:
            stream.seek(-release.VHD_FOOTER_BYTES, 2)
            stream.write(b"\0" * release.VHD_FOOTER_BYTES)
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_malformed_qemu_vhd_info(self):
        self.make_bundle("x86_64-full")
        info = self.azure / "x86_64-full" / "vhd-info.json"
        info.write_text(
            json.dumps({"format": "raw", "virtual-size": 2 * 1024**2}),
            encoding="utf-8",
        )
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_unrelated_structurally_valid_vhd(self):
        self.make_bundle("x86_64-full")
        vhd = self.azure / "x86_64-full" / "temporary.vhd"
        with vhd.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"unrelated")
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_conversion_parameter_mismatch(self):
        self.make_bundle("x86_64-full")
        attestation = (
            self.azure / "x86_64-full" / "conversion-attestation.json"
        )
        self.rewrite(
            attestation,
            lambda value: value["parameters"].__setitem__(
                "input_sha256", "0" * 64
            ),
        )
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_stage_rejects_mixed_uki_and_artifact_signing_identities(self):
        self.make_bundle("x86_64-full")
        self.make_bundle("aarch64-full", certificate_der=b"different certificate")
        with self.assertRaises(SystemExit):
            self.stage()
        shutil.rmtree(self.candidates / "aarch64-full")
        shutil.rmtree(self.azure / "aarch64-full")
        self.make_bundle(
            "aarch64-full", signing_certificate_sha256="5" * 64
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_azure_signing_binding_change(self):
        self.make_all()
        path = self.azure / "aarch64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("certificate_sha256", "0" * 64))
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_invalid_release_tag(self):
        self.make_all()
        with self.assertRaises(SystemExit):
            self.stage("Ubuntu-26.04-latest")

    def test_failed_stage_is_transactional(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        notes = self.root / "release-notes.md"
        notes.write_text("existing notes\n", encoding="utf-8")
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value["contracts"].pop())
        with self.assertRaises(SystemExit):
            self.stage()
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(notes.read_text(), "existing notes\n")
        self.assertEqual(list(self.root.glob(".*.tmp-*")), [])

    def test_notes_commit_failure_rolls_back_staged_assets(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        notes = self.root / "release-notes.md"
        notes.write_text("existing notes\n", encoding="utf-8")
        with mock.patch.object(release.os, "replace", side_effect=OSError("failure")):
            with self.assertRaises(OSError):
                self.stage()
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(notes.read_text(), "existing notes\n")

    def test_stage_refuses_nonempty_destination(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        (output / "do-not-replace").write_text("sentinel")
        with self.assertRaises(SystemExit):
            self.stage()
        self.assertTrue((output / "do-not-replace").is_file())

    def test_canonical_signature_verification_is_agent_free(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "ubuntu2604-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("std.base64.standard.Decoder", builder)
        self.assertIn('"gpgv", "--status-fd=1", "--keyring"', builder)
        self.assertNotIn('"gpg",', builder)
        self.assertNotIn('"--import"', builder)
        self.assertIn("gpgv mount", workflow)
        self.assertNotIn("gpg gpgv mount", workflow)
        self.assertNotIn("curl", workflow)

    def test_release_acquisition_uses_native_https_without_curl(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        self.assertIn("NativeHttpsDownloader.init", builder)
        self.assertIn("artifact_pipeline.acquireVerified", builder)
        self.assertIn("artifact_pipeline.downloadBoundedAtomic", builder)
        self.assertNotIn('"curl"', builder)

    def test_publisher_is_draft_first_allowlisted_and_fail_safe(self):
        script = (ROOT / "scripts" / "ubuntu2604_publish.sh").read_text()
        self.assertIn('test "$(wc -l <"$expected_file")" -eq 2', script)
        self.assertIn('"x86_64-full": "Ubuntu-26.04-x86_64.qcow2"', script)
        self.assertIn('"aarch64-full": "Ubuntu-26.04-aarch64.qcow2"', script)
        self.assertIn("--draft", script)
        self.assertIn("stale-asset-ids", script)
        self.assertIn("retaining $RELEASE_TAG as a draft", script)
        self.assertIn('gh release download "$RELEASE_TAG"', script)
        self.assertIn("downloaded digest mismatch", script)
        self.assertLess(
            script.index('gh release create "$RELEASE_TAG"'),
            script.index('gh release upload "$RELEASE_TAG"'),
        )
        self.assertLess(
            script.index("downloaded digest mismatch"),
            script.index('gh release edit "$RELEASE_TAG"', script.index("downloaded digest mismatch")),
        )


if __name__ == "__main__":
    unittest.main()
