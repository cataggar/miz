import base64
import hashlib
import json
import os
import shutil
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
        (provenance / "inputs.json").write_text(
            json.dumps({"snapshot": "ubuntu-26.04-test", "key": key}),
            encoding="utf-8",
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
                virtual_size=5 * 1024**3,
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
        current_size = release.AZURE_VHD_ALIGNMENT
        with vhd.open("wb") as stream:
            stream.truncate(current_size + release.VHD_FOOTER_BYTES)
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
        release.azure_result_command(
            types.SimpleNamespace(
                manifest=manifest,
                asset=asset,
                vhd=vhd,
                vhd_current_size=current_size,
                key=key,
                source_commit=self.source_commit,
                location="eastus2",
                vm_size="Standard_D2ds_v5",
                resource_group=f"ubuntu-{key}",
                image_version_id=(
                    f"/subscriptions/test/gallery/ubuntu/{key}/versions/1.0.0"
                ),
                uefi_request=request,
                uefi_response=response,
                run_id="100",
                run_attempt="1",
                output=azure_dir / "azure-result.json",
            )
        )
        vhd.unlink()

    def make_all(self) -> None:
        for key in release.EXPECTED:
            self.make_bundle(key)

    def stage(self, release_tag: str = "Ubuntu-26.04-20260818"):
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
        self.assertEqual(set(azure["contracts"]), release.AZURE_CONTRACTS)

    def test_candidate_rejects_validation_digest_mismatch(self):
        key = "x86_64-full"
        architecture, flavor, asset_name = release.EXPECTED[key]
        root = self.root / "candidate-only"
        provenance = root / "provenance"
        provenance.mkdir(parents=True)
        asset = root / asset_name
        asset.write_bytes(b"candidate")
        (provenance / "anything").write_bytes(b"provenance")
        with self.assertRaises(SystemExit):
            release.candidate_command(
                types.SimpleNamespace(
                    key=key,
                    architecture=architecture,
                    flavor=flavor,
                    asset=asset,
                    validated_sha256="0" * 64,
                    virtual_size=1,
                    source_commit=self.source_commit,
                    provenance_dir=provenance,
                    runner="runner",
                    run_id="1",
                    run_attempt="1",
                    output=root / "candidate.json",
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
        (provenance / "inputs.json").write_text("tampered", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        (provenance / "unbound.log").write_text("new", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def make_bundle_after_reset(self, key: str) -> None:
        shutil.rmtree(self.candidates / key)
        shutil.rmtree(self.azure / key)
        self.make_bundle(key)

    def test_stage_rejects_pem_der_and_embedded_private_keys(self):
        payloads = (
            b"-----BEGIN PRIVATE KEY-----\nsecret\n",
            b"\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00",
            b"prefix\n\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
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
                    / "inputs.json"
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
            lambda value: value.__setitem__(
                "derived_vhd_current_size",
                value["derived_vhd_current_size"] + release.AZURE_VHD_ALIGNMENT,
            ),
        )
        with self.assertRaises(SystemExit):
            self.stage()

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
