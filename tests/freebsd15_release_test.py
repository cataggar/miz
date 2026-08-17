import contextlib
import io
import json
import os
import re
import shutil
import types
import unittest
from pathlib import Path

from scripts import freebsd15_release as release


BUILDER_SOURCE = (
    Path(release.__file__).resolve().parent / "build_generalized_freebsd15.zig"
)
MANIFEST_SOURCE = (
    Path(release.__file__).resolve().parent / "freebsd15_package_manifest.zig"
)


def zig_string_list(source: str, name: str) -> list[str]:
    body = re.search(
        rf"pub const {name} = \[_\]\[\]const u8\{{(.*?)\n\}};",
        source,
        re.S,
    )
    if body is None:
        raise AssertionError(f"{name} is missing from the Zig manifest")
    return re.findall(r'"([^"]+)"', body.group(1))


def capture(handler, args) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        handler(args)
    return buffer.getvalue()


class FreeBSD15ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            Path.cwd()
            / ".scratch"
            / f"freebsd15-release-test-{os.getpid()}-{self._testMethodName}"
        )
        self.candidates = self.root / "candidates"
        self.output = self.root / "output"
        self.notes = self.root / "notes.md"
        self.azure_results = self.root / "azure-results"
        self.source_commit = "a" * 40
        self.release_date = "20260812"
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def candidate_arguments(self, key, **overrides):
        expected = release.VARIANTS[key]
        qemu_info = overrides.pop("qemu_info", None)
        if qemu_info is None:
            qemu_info = self.qemu_info(key, self.root)
        arguments = dict(
            architecture=expected["architecture"],
            filesystem=expected["filesystem"],
            flavor=expected["flavor"],
            package_manifest=self.package_manifest(key, self.root),
            asset=self.root / expected["asset_name"],
            validated_sha256="",
            virtual_size=expected["virtual_size"],
            qemu_info=qemu_info,
            source_name=expected["source_name"],
            source_url=release.source_url(key),
            source_sha256=expected["source_sha256"],
            source_bytes=123456789,
            source_commit=self.source_commit,
            qemu_version="QEMU emulator version 10.0.2",
            runner=expected["runner"],
            run_id="5001",
            run_attempt="7",
            output=self.root / "candidate.json",
        )
        arguments.update(overrides)
        return types.SimpleNamespace(**arguments)

    def qemu_info(self, key, directory, allocated_size=800):
        expected = release.VARIANTS[key]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{key}-qemu-info.json"
        path.write_text(
            json.dumps(
                {
                    "format": "qcow2",
                    "virtual-size": expected["virtual_size"],
                    "actual-size": allocated_size,
                    "backing-filename": "",
                    "format-specific": {
                        "data": {"compression-type": "zstd"}
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def package_manifest(self, key, directory, extra=(), drop=()):
        """Write a recorded manifest the way the builder would."""
        variant = release.VARIANTS[key]
        manifest = release.package_manifest(
            variant["filesystem"], variant["flavor"]
        )
        names = [
            name
            for name in (*manifest["required"], *manifest["library_roots"])
            if name not in drop
        ]
        names.extend(extra)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{release.VARIANTS[key]['asset_name']}.packages.txt"
        path.write_text(
            "".join(f"{name} 15.1 1024\n" for name in names), encoding="utf-8"
        )
        return path

    def make_candidate(
        self,
        key,
        source_commit=None,
        allocated_size=None,
        compressed_size=None,
    ):
        expected = release.VARIANTS[key]
        if allocated_size is None:
            allocated_size = 1000 if expected["flavor"] == "full" else 800
        if compressed_size is None:
            compressed_size = allocated_size
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True, exist_ok=True)
        asset = candidate_dir / expected["asset_name"]
        asset.write_bytes(b"x" * compressed_size)
        release.candidate_command(
            self.candidate_arguments(
                key,
                asset=asset,
                package_manifest=self.package_manifest(key, candidate_dir),
                validated_sha256=release.sha256(asset),
                qemu_info=self.qemu_info(
                    key,
                    candidate_dir,
                    allocated_size=allocated_size,
                ),
                source_commit=source_commit or self.source_commit,
                output=candidate_dir / "candidate.json",
            )
        )
        return candidate_dir / "candidate.json"

    def make_azure_result(self, key, source_commit=None, **overrides):
        candidate_path = self.candidates / key / "candidate.json"
        if not candidate_path.is_file():
            candidate_path = self.make_candidate(key)
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        document = {
            "schema": release.CANDIDATE_SCHEMA,
            "type": "vmiz-freebsd15-azure-acceptance",
            "variant": key,
            "architecture": release.VARIANTS[key]["architecture"],
            "filesystem": release.VARIANTS[key]["filesystem"],
            "flavor": release.VARIANTS[key]["flavor"],
            "asset_name": release.VARIANTS[key]["asset_name"],
            "source_commit": source_commit or self.source_commit,
            "qcow_sha256": candidate["asset_sha256"],
            "qcow_virtual_size": candidate["virtual_size"],
            "qcow_allocated_size": candidate["allocated_size"],
            "qcow_compressed_size": candidate["compressed_size"],
            "derived_vhd_sha256": "d" * 64,
            "derived_vhd_bytes": 7_340_544,
            "derived_vhd_current_size": 7_340_032,
            "status": "success",
            "location": "eastus2",
            "vm_size": "Standard_D2s_v5",
            "resource_group": "rg-vmiz-release",
            "contracts": list(
                release.azure_contracts(candidate["filesystem"])
            ),
            "workflow": {
                "run_id": candidate["validation"]["run_id"],
                "run_attempt": candidate["validation"]["run_attempt"],
            },
        }
        document.update(overrides)
        result_path = self.azure_results / key / "azure-result.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return result_path

    def test_candidate_records_all_three_sizes_from_validated_inputs(self):
        key = "aarch64-ufs-core"
        path = self.make_candidate(
            key,
            allocated_size=700,
            compressed_size=123,
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], 3)
        self.assertEqual(
            document["virtual_size"],
            release.VARIANTS[key]["virtual_size"],
        )
        self.assertEqual(document["allocated_size"], 700)
        self.assertEqual(document["compressed_size"], 123)
        self.assertEqual(
            document["validation"]["qemu_image"]["allocated_size"],
            700,
        )
        qemu_info = document["validation"]["qemu_info"]
        self.assertEqual(qemu_info["name"], "aarch64-ufs-core-qemu-info.json")
        self.assertEqual(
            qemu_info["sha256"],
            release.sha256(path.parent / qemu_info["name"]),
        )

    def stage(
        self,
        release_set,
        release_tag=None,
        release_date=...,
        azure_results=...,
        minimum_core_reduction_percent=None,
    ):
        if release_date is ...:
            release_date = self.release_date
        expected_release_tag, _ = release.release_identity(
            release_set,
            release_date,
        )
        if azure_results is ...:
            azure_results = self.azure_results
        release.stage_command(
            types.SimpleNamespace(
                release_set=release_set,
                candidates=self.candidates,
                source_commit=self.source_commit,
                release_tag=release_tag or expected_release_tag,
                release_date=release_date,
                azure_results=azure_results,
                minimum_core_reduction_percent=(
                    minimum_core_reduction_percent
                    if minimum_core_reduction_percent is not None
                    else release.CORE_MINIMUM_REDUCTION_PERCENT
                ),
                output=self.output,
                notes=self.notes,
            )
        )

    def stage_set(self, release_set):
        for key in release.RELEASE_SETS[release_set]["variants"]:
            size = 1000 if release.VARIANTS[key]["flavor"] == "full" else 800
            self.make_candidate(
                key,
                allocated_size=size,
                compressed_size=size,
            )
            self.make_azure_result(key)
        self.stage(release_set)

    def make_zfs_candidates(
        self,
        full_allocated=1000,
        full_compressed=1000,
        core_allocated=800,
        core_compressed=800,
        azure=True,
    ):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            is_full = release.VARIANTS[key]["flavor"] == "full"
            self.make_candidate(
                key,
                allocated_size=full_allocated if is_full else core_allocated,
                compressed_size=full_compressed if is_full else core_compressed,
            )
            if azure:
                self.make_azure_result(key)

    def test_stages_exact_four_asset_ufs_release(self):
        self.stage_set("zfs")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "zfs")
        self.assertEqual(
            manifest["release_tag"],
            f"FreeBSD-15.1-{self.release_date}",
        )
        self.assertEqual(
            {asset["asset_name"] for asset in manifest["assets"]},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
            },
        )
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
                "publish-manifest.json",
            },
        )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("## Full ZFS versus core evidence", notes)
        self.assertNotIn("baseline package manifests", notes.lower())
        self.assertIn("every published release asset", notes)
        self.assertIn("No `.sha256` or package-manifest sidecar assets", notes)
        self.assertIn(self.source_commit, notes)

    def test_stages_exact_two_asset_zfs_release(self):
        self.stage_set("zfs")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "zfs")
        self.assertEqual(
            manifest["release_tag"],
            f"FreeBSD-15.1-{self.release_date}",
        )
        self.assertEqual(
            {asset["asset_name"] for asset in manifest["assets"]},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
            },
        )
        self.assertEqual(
            {asset["filesystem"] for asset in manifest["assets"]}, {"zfs"}
        )
        for asset in manifest["assets"]:
            self.assertEqual(asset["azure"]["location"], "eastus2")
            self.assertEqual(asset["azure"]["vm_size"], "Standard_D2s_v5")
            self.assertGreater(asset["azure"]["derived_vhd_bytes"], 0)
            self.assertEqual(
                asset["azure"]["derived_vhd_bytes"],
                asset["azure"]["derived_vhd_current_size"]
                + release.VHD_FOOTER_BYTES,
            )
            self.assertEqual(
                asset["azure"]["contracts"],
                list(release.AZURE_CONTRACTS),
            )
        # The staging tree is the exact publication allowlist.
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
                "publish-manifest.json",
            },
        )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("full and core ZFS", notes)
        self.assertIn("zpool_reguid", notes)
        self.assertIn("Exact-candidate matching-architecture Gen2 validation", notes)
        self.assertNotIn("does not claim exact-candidate Azure validation", notes)
        self.assertIn("No `.sha256` or package-manifest sidecar assets", notes)


    def test_azure_result_command_emits_valid_document(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        output = self.root / "azure-result.json"
        vhd_sha256 = "f" * 64
        vhd_current_size = 8 * release.AZURE_VHD_ALIGNMENT
        vhd_bytes = vhd_current_size + release.VHD_FOOTER_BYTES
        contracts = ",".join(release.AZURE_CONTRACTS)

        release.azure_result_command(
            types.SimpleNamespace(
                manifest=candidate_path,
                asset=asset,
                key="x86_64-zfs-full",
                source_commit=self.source_commit,
                vhd_sha256=vhd_sha256,
                vhd_bytes=vhd_bytes,
                vhd_current_size=vhd_current_size,
                contracts=contracts,
                location="westus3",
                vm_size="Standard_D4s_v5",
                resource_group="rg-acceptance",
                run_id="5001",
                run_attempt="7",
                output=output,
            )
        )

        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], release.CANDIDATE_SCHEMA)
        self.assertEqual(document["type"], "vmiz-freebsd15-azure-acceptance")
        self.assertEqual(document["variant"], "x86_64-zfs-full")
        self.assertEqual(document["architecture"], "x86_64")
        self.assertEqual(document["filesystem"], "zfs")
        self.assertEqual(document["flavor"], "full")
        self.assertEqual(
            document["asset_name"],
            release.VARIANTS["x86_64-zfs-full"]["asset_name"],
        )
        self.assertEqual(document["source_commit"], self.source_commit)
        self.assertEqual(document["qcow_sha256"], candidate["asset_sha256"])
        self.assertEqual(
            document["qcow_virtual_size"],
            candidate["virtual_size"],
        )
        self.assertEqual(
            document["qcow_allocated_size"],
            candidate["allocated_size"],
        )
        self.assertEqual(
            document["qcow_compressed_size"],
            candidate["compressed_size"],
        )
        self.assertNotIn("azure_accepted_sha256", document)
        self.assertEqual(document["derived_vhd_sha256"], vhd_sha256)
        self.assertEqual(document["derived_vhd_bytes"], vhd_bytes)
        self.assertEqual(
            document["derived_vhd_current_size"],
            vhd_current_size,
        )
        self.assertEqual(document["status"], "success")
        self.assertEqual(document["location"], "westus3")
        self.assertEqual(document["vm_size"], "Standard_D4s_v5")
        self.assertEqual(document["resource_group"], "rg-acceptance")
        self.assertEqual(document["contracts"], list(release.AZURE_CONTRACTS))
        self.assertEqual(
            document["workflow"], {"run_id": "5001", "run_attempt": "7"}
        )

    def test_azure_result_supports_ufs_full_and_core_contracts(self):
        for key in ("x86_64-ufs-full", "aarch64-ufs-core"):
            with self.subTest(key=key):
                candidate_path = self.make_candidate(key)
                candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
                asset = candidate_path.parent / candidate["asset_name"]
                output = self.root / f"{key}-azure-result.json"
                contracts = release.azure_contracts("ufs")
                release.azure_result_command(
                    types.SimpleNamespace(
                        manifest=candidate_path,
                        asset=asset,
                        key=key,
                        source_commit=self.source_commit,
                        vhd_sha256="f" * 64,
                        vhd_bytes=release.AZURE_VHD_ALIGNMENT
                        + release.VHD_FOOTER_BYTES,
                        vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                        contracts=",".join(contracts),
                        location="westus3",
                        vm_size="Standard_D4s_v5",
                        resource_group="rg-acceptance",
                        run_id="5001",
                        run_attempt="7",
                        output=output,
                    )
                )
                document = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(document["schema"], release.CANDIDATE_SCHEMA)
                self.assertEqual(document["filesystem"], "ufs")
                self.assertEqual(document["flavor"], candidate["flavor"])
                self.assertEqual(document["contracts"], list(contracts))
                self.assertEqual(
                    document["qcow_allocated_size"],
                    candidate["allocated_size"],
                )

    def test_azure_result_rejects_cross_filesystem_contracts(self):
        candidate_path = self.make_candidate("x86_64-ufs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        with self.assertRaisesRegex(ValueError, "contracts"):
            release.azure_result_command(
                types.SimpleNamespace(
                    manifest=candidate_path,
                    asset=asset,
                    key="x86_64-ufs-full",
                    source_commit=self.source_commit,
                    vhd_sha256="f" * 64,
                    vhd_bytes=release.AZURE_VHD_ALIGNMENT
                    + release.VHD_FOOTER_BYTES,
                    vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                    contracts=",".join(release.AZURE_CONTRACTS),
                    location="westus3",
                    vm_size="Standard_D4s_v5",
                    resource_group="rg-acceptance",
                    run_id="5001",
                    run_attempt="7",
                    output=self.root / "azure-result.json",
                )
            )

    def test_azure_result_rejects_variant_mismatch(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        with self.assertRaisesRegex(ValueError, "variant"):
            release.azure_result_command(
                types.SimpleNamespace(
                    manifest=candidate_path,
                    asset=asset,
                    key="aarch64-zfs-full",
                    source_commit=self.source_commit,
                    vhd_sha256="f" * 64,
                    vhd_bytes=release.AZURE_VHD_ALIGNMENT
                    + release.VHD_FOOTER_BYTES,
                    vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                    contracts=",".join(release.AZURE_CONTRACTS),
                    location="westus3",
                    vm_size="Standard_D4s_v5",
                    resource_group="rg-acceptance",
                    run_id="5001",
                    run_attempt="7",
                    output=self.root / "azure-result.json",
                )
            )

    def test_azure_result_rejects_invalid_vhd_sha256(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        with self.assertRaisesRegex(ValueError, "VHD SHA-256"):
            release.azure_result_command(
                types.SimpleNamespace(
                    manifest=candidate_path,
                    asset=asset,
                    key="x86_64-zfs-full",
                    source_commit=self.source_commit,
                    vhd_sha256="not-a-sha",
                    vhd_bytes=release.AZURE_VHD_ALIGNMENT
                    + release.VHD_FOOTER_BYTES,
                    vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                    contracts=",".join(release.AZURE_CONTRACTS),
                    location="westus3",
                    vm_size="Standard_D4s_v5",
                    resource_group="rg-acceptance",
                    run_id="5001",
                    run_attempt="7",
                    output=self.root / "azure-result.json",
                )
            )

    def test_azure_result_rejects_invalid_contracts(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        with self.assertRaisesRegex(ValueError, "contracts"):
            release.azure_result_command(
                types.SimpleNamespace(
                    manifest=candidate_path,
                    asset=asset,
                    key="x86_64-zfs-full",
                    source_commit=self.source_commit,
                    vhd_sha256="f" * 64,
                    vhd_bytes=release.AZURE_VHD_ALIGNMENT
                    + release.VHD_FOOTER_BYTES,
                    vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                    contracts="key-only-ssh,agent-ready",
                    location="westus3",
                    vm_size="Standard_D4s_v5",
                    resource_group="rg-acceptance",
                    run_id="5001",
                    run_attempt="7",
                    output=self.root / "azure-result.json",
                )
            )

    def test_azure_result_rejects_empty_location(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        with self.assertRaisesRegex(ValueError, "location"):
            release.azure_result_command(
                types.SimpleNamespace(
                    manifest=candidate_path,
                    asset=asset,
                    key="x86_64-zfs-full",
                    source_commit=self.source_commit,
                    vhd_sha256="f" * 64,
                    vhd_bytes=release.AZURE_VHD_ALIGNMENT
                    + release.VHD_FOOTER_BYTES,
                    vhd_current_size=release.AZURE_VHD_ALIGNMENT,
                    contracts=",".join(release.AZURE_CONTRACTS),
                    location="",
                    vm_size="Standard_D4s_v5",
                    resource_group="rg-acceptance",
                    run_id="5001",
                    run_attempt="7",
                    output=self.root / "azure-result.json",
                )
            )

    def test_zfs_stage_requires_azure_results(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_candidate(key)
        with self.assertRaisesRegex(ValueError, "azure-results"):
            self.stage("zfs", azure_results=None)

    def test_zfs_stage_with_valid_azure_results(self):
        self.stage_set("zfs")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        for asset in manifest["assets"]:
            self.assertEqual(asset["azure"]["location"], "eastus2")
            self.assertEqual(asset["azure"]["vm_size"], "Standard_D2s_v5")
            self.assertGreater(asset["azure"]["derived_vhd_bytes"], 0)
            self.assertEqual(
                asset["azure"]["derived_vhd_bytes"],
                asset["azure"]["derived_vhd_current_size"]
                + release.VHD_FOOTER_BYTES,
            )
            self.assertEqual(
                asset["azure"]["contracts"],
                list(release.AZURE_CONTRACTS),
            )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("## Azure validation", notes)
        self.assertIn("Exact-candidate matching-architecture Gen2 validation", notes)
        self.assertIn("eastus2", notes)
        self.assertIn("Standard_D2s_v5", notes)
        self.assertNotIn("does not claim exact-candidate Azure validation", notes)

    def test_zfs_stage_rejects_missing_azure_result(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_candidate(key)
        self.make_azure_result("aarch64-zfs-full")
        with self.assertRaisesRegex(ValueError, "expected 4 azure result"):
            self.stage("zfs")

    def test_zfs_stage_rejects_cross_variant_azure_result(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = (
            self.azure_results
            / "x86_64-zfs-core"
            / "azure-result.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        document["variant"] = "aarch64-zfs-full"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate aarch64-zfs-full"):
            self.stage("zfs")

    def test_zfs_stage_rejects_cross_commit_azure_result(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = self.azure_results / "x86_64-zfs-full" / "azure-result.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["source_commit"] = "b" * 40
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            self.stage("zfs")

    def test_zfs_stage_rejects_inconsistent_vhd_current_size_evidence(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = self.azure_results / "x86_64-zfs-full" / "azure-result.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["derived_vhd_current_size"] += release.AZURE_VHD_ALIGNMENT
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "size evidence"):
            self.stage("zfs")

    def test_zfs_stage_rejects_cross_workflow_azure_result(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = self.azure_results / "x86_64-zfs-full" / "azure-result.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["workflow"]["run_attempt"] = "8"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "workflow identity"):
            self.stage("zfs")

    def test_zfs_stage_rejects_tampered_qcow_digest(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = self.azure_results / "x86_64-zfs-full" / "azure-result.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["qcow_sha256"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "QCOW SHA-256"):
            self.stage("zfs")

    def test_zfs_stage_rejects_tampered_qcow_size_binding(self):
        for field in ("qcow_allocated_size", "qcow_compressed_size"):
            with self.subTest(field=field):
                shutil.rmtree(self.candidates, ignore_errors=True)
                shutil.rmtree(self.azure_results, ignore_errors=True)
                for key in release.RELEASE_SETS["zfs"]["variants"]:
                    self.make_azure_result(key)
                path = (
                    self.azure_results
                    / "x86_64-zfs-full"
                    / "azure-result.json"
                )
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] += 1
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "does not match candidate"):
                    self.stage("zfs")

    def test_zfs_stage_rejects_incomplete_contracts(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_azure_result(key)
        path = (
            self.azure_results
            / "x86_64-zfs-core"
            / "azure-result.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        document["contracts"] = list(release.AZURE_CONTRACTS[:-1])
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contracts"):
            self.stage("zfs")

    def test_ufs_stage_binds_schema3_digest_sizes_commit_and_contracts(self):
        mutations = (
            ("schema", release.CANDIDATE_SCHEMA - 1, "unsupported schema"),
            ("qcow_sha256", "0" * 64, "QCOW SHA-256"),
            ("qcow_allocated_size", 801, "does not match candidate"),
            ("qcow_compressed_size", 999, "does not match candidate"),
            ("source_commit", "b" * 40, "source commit mismatch"),
            ("contracts", ["matching-architecture-gen2"], "contracts"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                shutil.rmtree(self.candidates, ignore_errors=True)
                shutil.rmtree(self.azure_results, ignore_errors=True)
                self.make_zfs_candidates()
                path = (
                    self.azure_results
                    / "x86_64-zfs-core"
                    / "azure-result.json"
                )
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = value
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    self.stage("zfs")

    def test_ufs_stage_requires_azure_results(self):
        self.make_zfs_candidates(azure=False)
        with self.assertRaisesRegex(ValueError, "zfs releases require"):
            self.stage("zfs", azure_results=None)

    def test_ufs_stage_rejects_missing_azure_result(self):
        self.make_zfs_candidates()
        (self.azure_results / "aarch64-zfs-full" / "azure-result.json").unlink()
        with self.assertRaisesRegex(ValueError, "expected 4 azure result"):
            self.stage("zfs")

    def test_rejects_incomplete_matrix(self):
        self.make_candidate("aarch64-zfs-full")
        with self.assertRaisesRegex(ValueError, "expected 4 candidate manifests"):
            self.stage("zfs")

    def test_rejects_candidates_from_another_release_set(self):
        self.make_candidate("aarch64-zfs-full")
        self.make_candidate("x86_64-zfs-full")
        self.make_candidate("aarch64-zfs-core")
        self.make_candidate("x86_64-ufs-full")
        with self.assertRaisesRegex(ValueError, "incomplete or unexpected"):
            self.stage("zfs")

    def test_rejects_a_tag_belonging_to_another_release_set(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_candidate(key)
        with self.assertRaisesRegex(ValueError, "must be tagged"):
            self.stage("zfs", release_tag="FreeBSD-15.1-20260724")

    def test_rejects_changed_candidate(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_candidate(key)
        changed = (
            self.candidates
            / "x86_64-zfs-full"
            / release.VARIANTS["x86_64-zfs-full"]["asset_name"]
        )
        changed.write_bytes(b"tampered candidate\n")
        with self.assertRaisesRegex(ValueError, "candidate (size|digest) mismatch"):
            self.stage("zfs")

    def test_rejects_mismatched_source_commit(self):
        for key in release.RELEASE_SETS["zfs"]["variants"]:
            self.make_candidate(
                key,
                source_commit=(
                    "b" * 40 if key == "x86_64-zfs-full" else self.source_commit
                ),
            )
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            self.stage("zfs")

    def test_candidate_rejects_unpinned_sources(self):
        key = "aarch64-zfs-full"
        asset = self.root / release.VARIANTS[key]["asset_name"]
        asset.write_bytes(b"candidate\n")
        digest = release.sha256(asset)

        cases = {
            "source SHA-256 does not match": {"source_sha256": "0" * 64},
            "source filename does not match": {
                "source_name": release.VARIANTS["aarch64-ufs-full"]["source_name"]
            },
            "source URL does not match": {
                "source_url": "https://example.invalid/image.qcow2.xz"
            },
            "virtual size does not match": {"virtual_size": 1},
            "validated SHA-256 does not match": {"validated_sha256": "0" * 64},
        }
        for message, override in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    release.candidate_command(
                        self.candidate_arguments(
                            key,
                            **{
                                "asset": asset,
                                "validated_sha256": digest,
                                **override,
                            },
                        )
                    )

    def test_candidate_rejects_qemu_info_without_allocated_size(self):
        key = "aarch64-ufs-core"
        asset = self.root / release.VARIANTS[key]["asset_name"]
        asset.write_bytes(b"candidate\n")
        qemu_info = self.qemu_info(key, self.root)
        document = json.loads(qemu_info.read_text(encoding="utf-8"))
        del document["actual-size"]
        qemu_info.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "qemu-img allocated size"):
            release.candidate_command(
                self.candidate_arguments(
                    key,
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                    qemu_info=qemu_info,
                )
            )

    def test_stage_rejects_missing_allocated_size(self):
        self.make_zfs_candidates()
        manifest_path = self.candidates / "aarch64-zfs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        del document["allocated_size"]
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "allocated size"):
            self.stage("zfs")

    def test_stage_rejects_tampered_allocated_size(self):
        self.make_zfs_candidates()
        manifest_path = self.candidates / "x86_64-zfs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["allocated_size"] += 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "qemu-img size metadata mismatch"):
            self.stage("zfs")

    def test_stage_rejects_tampered_qemu_info_input(self):
        self.make_zfs_candidates()
        manifest_path = self.candidates / "aarch64-zfs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        qemu_info = manifest_path.parent / document["validation"]["qemu_info"]["name"]
        qemu_document = json.loads(qemu_info.read_text(encoding="utf-8"))
        qemu_document["actual-size"] += 1
        qemu_info.write_text(json.dumps(qemu_document), encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError,
            "qemu-img validation input mismatch",
        ):
            self.stage("zfs")

    def test_stage_rejects_legacy_candidate_schema(self):
        self.make_zfs_candidates()
        manifest_path = self.candidates / "aarch64-zfs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["schema"] = release.CANDIDATE_SCHEMA - 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            self.stage("zfs")

    def test_candidate_rejects_a_cross_filesystem_asset_name(self):
        asset = self.root / release.VARIANTS["aarch64-zfs-full"]["asset_name"]
        asset.write_bytes(b"candidate\n")
        with self.assertRaisesRegex(ValueError, "asset must be"):
            release.candidate_command(
                self.candidate_arguments(
                    "aarch64-zfs-core",
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                )
            )

    def test_matrix_covers_exact_release_assets(self):
        for name, selected in release.RELEASE_SETS.items():
            with self.subTest(release_set=name):
                matrix = json.loads(
                    capture(
                        release.matrix_command,
                        types.SimpleNamespace(release_set=name),
                    )
                )
                self.assertEqual(
                    [entry["variant"] for entry in matrix["include"]],
                    list(release.build_variants(name)),
                )
                for entry in matrix["include"]:
                    variant = release.VARIANTS[entry["variant"]]
                    self.assertEqual(entry["asset_name"], variant["asset_name"])
                    self.assertEqual(
                        entry["source_sha256"], variant["source_sha256"]
                    )
                    self.assertEqual(
                        entry["virtual_size"], variant["virtual_size"]
                    )
                    self.assertTrue(
                        entry["source_url"].startswith(release.SOURCE_URL_PREFIX)
                    )
                    self.assertTrue(
                        entry["source_url"].endswith("/" + entry["source_name"])
                    )
                    self.assertEqual(entry["release_role"], "release")

    def test_azure_matrix_is_exact_for_gated_release_sets(self):
        expected = {
            "zfs": list(release.RELEASE_SETS["zfs"]["variants"]),
        }
        for name, variants in expected.items():
            with self.subTest(release_set=name):
                matrix = json.loads(
                    capture(
                        release.azure_matrix_command,
                        types.SimpleNamespace(release_set=name),
                    )
                )
                self.assertEqual(
                    [entry["key"] for entry in matrix["include"]],
                    variants,
                )
                for entry in matrix["include"]:
                    profile = release.VARIANTS[entry["key"]]
                    self.assertEqual(entry["architecture"], profile["architecture"])
                    self.assertEqual(entry["filesystem"], profile["filesystem"])
                    self.assertEqual(entry["flavor"], profile["flavor"])
                    self.assertEqual(entry["asset_name"], profile["asset_name"])
                    suffix = (
                        "ARM64"
                        if profile["architecture"] == "aarch64"
                        else "X64"
                    )
                    self.assertEqual(
                        entry["location_variable"],
                        f"AZURE_LOCATION_{suffix}",
                    )
                    self.assertEqual(
                        entry["size_variable"],
                        f"AZURE_VM_SIZE_{suffix}",
                    )

    def test_core_and_full_profiles_share_pinned_sources(self):
        for filesystem in ("ufs", "zfs"):
            for architecture in ("aarch64", "x86_64"):
                full_key = f"{architecture}-{filesystem}-full"
                core_key = f"{architecture}-{filesystem}-core"
                for field in ("source_name", "source_sha256", "virtual_size"):
                    self.assertEqual(
                        release.VARIANTS[full_key][field],
                        release.VARIANTS[core_key][field],
                    )
                self.assertEqual(
                    release.source_url(full_key),
                    release.source_url(core_key),
                )

    def test_unsupported_variant_combinations_fail_closed(self):
        for architecture, filesystem, flavor in (
            ("riscv64", "ufs", "core"),
            ("x86_64", "ufs", "minimal"),
        ):
            with self.subTest(
                architecture=architecture,
                filesystem=filesystem,
                flavor=flavor,
            ):
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    release.variant_key(architecture, filesystem, flavor)

    def test_describe_reports_the_selected_release_set(self):
        output = capture(
            release.describe_command,
            types.SimpleNamespace(
                release_set="zfs",
                release_date=self.release_date,
            ),
        )
        self.assertIn(
            f"release_tag=FreeBSD-15.1-{self.release_date}\n",
            output,
        )
        self.assertIn(
            f"release_title=FreeBSD 15.1 - {self.release_date}\n",
            output,
        )
        self.assertIn("asset_count=4\n", output)
        self.assertIn("core_minimum_reduction_percent=10\n", output)

    def test_ufs_describe_requires_an_explicit_valid_release_date(self):
        for value in (None, "", "2026073", "20260230"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "release date"):
                    release.describe_command(
                        types.SimpleNamespace(
                            release_set="zfs",
                            release_date=value,
                        )
                    )
        output = capture(
            release.describe_command,
            types.SimpleNamespace(
                release_set="zfs",
                release_date=self.release_date,
            ),
        )
        self.assertIn(
            f"release_tag=FreeBSD-15.1-{self.release_date}\n",
            output,
        )
        self.assertIn("asset_count=4\n", output)

    def test_ufs_rejects_the_historical_full_only_tag(self):
        with self.assertRaisesRegex(
            ValueError,
            "belongs to historical full UFS release",
        ):
            release.release_identity("zfs", "20260724")
        with self.assertRaisesRegex(
            ValueError,
            "belongs to historical full UFS release",
        ):
            release.validate_release_tag("zfs", "FreeBSD-15.1-20260724")

    def test_rejects_the_historical_qualified_zfs_tag(self):
        self.assertIn(
            "FreeBSD-15.1-zfs-20260729",
            release.RESERVED_RELEASE_TAGS,
        )
        with self.assertRaisesRegex(ValueError, "release date"):
            release.validate_release_tag(
                "zfs",
                "FreeBSD-15.1-zfs-20260729",
            )

    def test_release_sets_partition_every_variant_exactly_once(self):
        claimed = [
            key
            for selected in release.RELEASE_SETS.values()
            for key in selected["variants"]
        ]
        self.assertEqual(
            claimed,
            list(release.RELEASE_SETS["zfs"]["variants"]),
        )
        self.assertTrue(
            all(release.VARIANTS[key]["filesystem"] == "zfs" for key in claimed)
        )
        tags = {
            release.release_identity(
                name,
                self.release_date,
            )[0]
            for name in release.RELEASE_SETS
        }
        self.assertEqual(len(tags), len(release.RELEASE_SETS))
        names = {release.VARIANTS[key]["asset_name"] for key in claimed}
        self.assertEqual(len(names), len(claimed))

    def test_variant_table_matches_the_zig_builder_profiles(self):
        source = BUILDER_SOURCE.read_text(encoding="utf-8")
        profiles = re.findall(
            r"\.architecture = \.(\w+),\s*"
            r"\.flavor = \.(\w+),\s*"
            r"\.root_storage = (\w+)_root_storage,\s*"
            r'\.source_name = "([^"]+)",\s*'
            r'\.source_url = "([^"]+)",\s*'
            r'\.source_sha256 = "([0-9a-f]{64})",\s*'
            r"\.virtual_size = ([0-9_]+),\s*"
            r'\.output = "([^"]+)",',
            source,
        )
        seen = set()
        for (
            architecture,
            flavor,
            filesystem,
            source_name,
            url,
            digest,
            virtual_size,
            output,
        ) in profiles:
            key = release.variant_key(architecture, filesystem, flavor)
            seen.add(key)
            variant = release.VARIANTS[key]
            self.assertEqual(source_name, variant["source_name"])
            self.assertEqual(url, release.source_url(key))
            self.assertEqual(digest, variant["source_sha256"])
            self.assertEqual(
                int(virtual_size.replace("_", "")), variant["virtual_size"]
            )
            if filesystem == "zfs":
                self.assertIn(
                    output,
                    {
                        variant["asset_name"],
                        variant["asset_name"].replace(".qcow2", ".zfs.qcow2"),
                    },
                )
            else:
                self.assertEqual(output, variant["asset_name"])
        self.assertIn(
            seen,
            (
                set(release.VARIANTS),
                set(release.VARIANTS)
                - {"aarch64-zfs-core", "x86_64-zfs-core"},
            ),
        )

    def test_package_manifests_match_the_zig_manifest(self):
        source = MANIFEST_SOURCE.read_text(encoding="utf-8")
        required = re.findall(
            r'\.name = "([^"]+)",\s*\.source = \.\w+,', source
        )
        self.assertEqual(
            list(release.SHARED_REQUIRED_PACKAGES),
            [
                name
                for name in required
                if name
                not in (
                    "FreeBSD-ufs",
                    "FreeBSD-ufs-lib",
                    "FreeBSD-zfs",
                    "FreeBSD-zfs-lib",
                )
            ],
        )
        self.assertEqual(
            release.FILESYSTEM_REQUIRED_PACKAGES,
            {
                "ufs": ("FreeBSD-ufs", "FreeBSD-ufs-lib"),
                "zfs": ("FreeBSD-zfs", "FreeBSD-zfs-lib"),
            },
        )
        for packages in release.FILESYSTEM_REQUIRED_PACKAGES.values():
            for package in packages:
                self.assertIn(f'.name = "{package}"', source)
        self.assertEqual(
            list(release.LIBRARY_ROOTS), zig_string_list(source, "library_roots")
        )
        self.assertEqual(
            list(release.CORE_EXCLUDED_PACKAGES),
            zig_string_list(source, "core_excluded_packages"),
        )
        self.assertEqual(
            list(release.CORE_EXCLUDED_CLASSES),
            zig_string_list(source, "core_excluded_classes"),
        )
        self.assertEqual(release.PACKAGE_MANIFEST_REVISION, 3)
        flavors = re.findall(r"pub fn parse.*?\}", source, re.S)[0]
        self.assertEqual(
            sorted(re.findall(r'"(\w+)"', flavors)),
            ["core", "full"],
        )
        self.assertEqual(
            set(release.PACKAGE_MANIFESTS),
            {"ufs", "zfs"},
        )

    def test_retained_contract_covers_every_required_capability(self):
        # Each entry is a capability the issue's retain-at-minimum list names
        # and the package that must still deliver it in a core image.
        contract = {
            "UEFI boot": "FreeBSD-bootloader",
            "release kernel": "FreeBSD-kernel-generic",
            "virtio and Hyper-V": "FreeBSD-hyperv-tools",
            "rc": "FreeBSD-rc",
            "sysrc configuration": "FreeBSD-bsdconfig",
            "user and account management": "FreeBSD-runtime",
            "DNS": "FreeBSD-resolvconf",
            "DHCP": "FreeBSD-dhclient",
            "certificates": "FreeBSD-caroot",
            "entropy and time": "FreeBSD-ntp",
            "key-only OpenSSH": "FreeBSD-ssh",
            "recovery tools": "FreeBSD-rescue",
            "nuageinit provisioning": "FreeBSD-nuageinit",
            "pkg": "pkg",
            "FreeBSD-base updates": "FreeBSD-pkg-bootstrap",
            "Azure Agent": "azure-agent",
        }
        for capability, package in contract.items():
            with self.subTest(capability=capability):
                self.assertIn(package, release.SHARED_REQUIRED_PACKAGES)
                for filesystem, flavors in release.PACKAGE_MANIFESTS.items():
                    for flavor, manifest in flavors.items():
                        self.assertIn(package, manifest["required"], flavor)
                        self.assertNotIn(package, manifest["excluded"], flavor)
                        with self.assertRaisesRegex(
                            ValueError, f"missing {package}"
                        ):
                            release.verify_package_manifest(
                                filesystem,
                                flavor,
                                [
                                    {"name": name}
                                    for name in manifest["required"]
                                    if name != package
                                ],
                            )
        for filesystem, packages in (
            ("ufs", ("FreeBSD-ufs", "FreeBSD-ufs-lib")),
            ("zfs", ("FreeBSD-zfs", "FreeBSD-zfs-lib")),
        ):
            with self.subTest(filesystem=filesystem):
                for flavor in ("full", "core"):
                    manifest = release.package_manifest(filesystem, flavor)
                    for package in packages:
                        self.assertIn(package, manifest["required"])
                    other = (
                        ("FreeBSD-zfs", "FreeBSD-zfs-lib")
                        if filesystem == "ufs"
                        else ("FreeBSD-ufs", "FreeBSD-ufs-lib")
                    )
                    for package in other:
                        self.assertNotIn(package, manifest["required"])

    def test_core_retains_exact_sysrc_provider_without_broad_sets(self):
        core = release.package_manifest("zfs", "core")
        self.assertEqual(release.PACKAGE_MANIFEST_REVISION, 3)
        self.assertIn("FreeBSD-bsdconfig", core["required"])
        for broad_set in (
            "FreeBSD-set-base",
            "FreeBSD-set-devel",
            "FreeBSD-set-optional",
        ):
            self.assertNotIn(broad_set, core["required"])
            self.assertIn(broad_set, core["excluded"])

    def test_verify_package_manifest_rejects_excluded_content(self):
        required = release.package_manifest("zfs", "core")["required"]
        retained = [{"name": name} for name in required]
        release.verify_package_manifest("zfs", "core", retained)
        for name in ("FreeBSD-clang", "FreeBSD-runtime-dbg", "FreeBSD-clibs-dev"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "still carries"):
                    release.verify_package_manifest(
                        "zfs", "core", retained + [{"name": name}]
                    )
        # A third-party package that merely ends in an excluded class is not a
        # pkgbase family member, and the full flavor excludes nothing.
        release.verify_package_manifest(
            "zfs", "core", retained + [{"name": "py312-dev"}]
        )
        release.verify_package_manifest(
            "zfs", "full", retained + [{"name": "FreeBSD-clang"}]
        )

    def test_parse_package_manifest_rejects_malformed_records(self):
        path = self.root / "packages.txt"
        for text in ("", "FreeBSD-runtime 15.1\n", "a 1 x\n", "a 1 2\na 2 3\n"):
            with self.subTest(text=text):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    release.parse_package_manifest(path)
        path.write_text("FreeBSD-runtime 15.1 2048\n", encoding="utf-8")
        self.assertEqual(
            release.parse_package_manifest(path),
            [
                {
                    "name": "FreeBSD-runtime",
                    "version": "15.1",
                    "installed_bytes": 2048,
                }
            ],
        )

    def test_core_candidate_rejects_a_manifest_missing_the_contract(self):
        key = "aarch64-ufs-core"
        asset = self.root / release.VARIANTS[key]["asset_name"]
        asset.write_bytes(b"candidate\n")
        with self.assertRaisesRegex(ValueError, "missing FreeBSD-ssh"):
            release.candidate_command(
                self.candidate_arguments(
                    key,
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                    package_manifest=self.package_manifest(
                        key, self.root / "pruned", drop=("FreeBSD-ssh",)
                    ),
                )
            )

    def test_core_candidate_rejects_a_manifest_carrying_an_exclusion(self):
        key = "x86_64-ufs-core"
        asset = self.root / release.VARIANTS[key]["asset_name"]
        asset.write_bytes(b"candidate\n")
        with self.assertRaisesRegex(ValueError, "still carries FreeBSD-clang"):
            release.candidate_command(
                self.candidate_arguments(
                    key,
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                    package_manifest=self.package_manifest(
                        key, self.root / "fat", extra=("FreeBSD-clang",)
                    ),
                )
            )

    def test_stage_rejects_a_candidate_whose_recorded_manifest_was_edited(self):
        self.make_zfs_candidates()
        manifest_path = self.candidates / "x86_64-zfs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["packages"]["names"].append("FreeBSD-tests")
        document["packages"]["count"] += 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "still carries FreeBSD-tests"):
            self.stage("zfs")

    def test_core_size_gate_accepts_the_threshold_boundary_for_both_architectures(
        self,
    ):
        self.make_zfs_candidates(
            core_allocated=900,
            core_compressed=900,
        )
        self.stage("zfs", minimum_core_reduction_percent=10)
        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {asset["flavor"] for asset in manifest["assets"]},
            {"full", "core"},
        )

    def test_core_size_gate_rejects_a_regression_on_either_architecture(self):
        self.make_zfs_candidates(
            core_allocated=900,
            core_compressed=900,
        )
        self.make_candidate(
            "x86_64-zfs-core",
            allocated_size=901,
            compressed_size=900,
        )
        self.make_azure_result("x86_64-zfs-core")
        with self.assertRaisesRegex(
            ValueError,
            "x86_64 core allocated size reduction is below 10%",
        ):
            self.stage("zfs", minimum_core_reduction_percent=10)

    def test_core_size_gate_rejects_compressed_size_regression(self):
        self.make_zfs_candidates(
            core_allocated=900,
            core_compressed=900,
        )
        self.make_candidate(
            "aarch64-zfs-core",
            allocated_size=900,
            compressed_size=901,
        )
        self.make_azure_result("aarch64-zfs-core")
        with self.assertRaisesRegex(
            ValueError,
            "aarch64 core compressed/download size reduction is below 10%",
        ):
            self.stage("zfs", minimum_core_reduction_percent=10)

    def test_core_size_gate_honors_a_reviewed_threshold_override(self):
        self.make_zfs_candidates(
            core_allocated=850,
            core_compressed=850,
        )
        with self.assertRaisesRegex(ValueError, "below 20%"):
            self.stage("zfs", minimum_core_reduction_percent=20)

    def test_core_size_gate_rejects_zero_or_noop_thresholds(self):
        for threshold in (0, 100, True):
            with self.subTest(threshold=threshold):
                with self.assertRaisesRegex(ValueError, "from 1 to 99"):
                    release.require_reduction_percent(threshold)

    def test_full_core_pairing_rejects_source_or_identity_mismatch(self):
        self.stage_set("zfs")
        path = self.output / "publish-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        core = next(
            asset
            for asset in manifest["assets"]
            if asset["variant"] == "aarch64-zfs-core"
        )
        core["source"]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "pinned sources differ"):
            release.full_core_rows(manifest)

        manifest = json.loads(path.read_text(encoding="utf-8"))
        core = next(
            asset
            for asset in manifest["assets"]
            if asset["variant"] == "aarch64-zfs-core"
        )
        core["architecture"] = "x86_64"
        with self.assertRaisesRegex(ValueError, "identity is invalid"):
            release.full_core_rows(manifest)

    def test_ufs_stage_rejects_an_incomplete_four_candidate_matrix(self):
        for key in release.RELEASE_SETS["zfs"]["variants"][:-1]:
            self.make_azure_result(key)
        with self.assertRaisesRegex(ValueError, "expected 4 candidate manifests"):
            self.stage("zfs")

    def test_compare_reports_all_sizes_for_both_architectures(self):
        self.stage_set("zfs")
        manifest = self.output / "publish-manifest.json"

        report = capture(
            release.compare_command,
            types.SimpleNamespace(
                candidate=manifest,
                output=self.root / "comparison.md",
            ),
        )
        self.assertIn("| aarch64 |", report)
        self.assertIn("| x86_64 |", report)
        self.assertIn("Full virtual", report)
        self.assertIn("Full allocated", report)
        self.assertIn("Full compressed/download", report)
        self.assertIn("| 1000 | 800 | 20.0%", report)
        self.assertIn("6477643776", report)
        self.assertIn("6477840384", report)
        self.assertEqual(
            (self.root / "comparison.md").read_text(encoding="utf-8"), report
        )

    def test_compare_rejects_legacy_publish_schema(self):
        self.stage_set("zfs")
        manifest_path = self.output / "publish-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema"] = release.CANDIDATE_SCHEMA - 1
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            release.compare_command(
                types.SimpleNamespace(
                    candidate=manifest_path,
                    output=None,
                )
            )


    def test_azure_acceptance_harness_invocation_matches_parser(self):
        """Static assertion: the shell harness calls azure-result with exactly
        the arguments the Python parser expects."""
        harness = (
            Path(release.__file__).resolve().parent
            / "freebsd15_azure_acceptance.sh"
        )
        source = harness.read_text(encoding="utf-8")
        # Extract the argument names from the harness invocation block.
        invocation = re.search(
            r"python3 scripts/freebsd15_release\.py azure-result\b(.*?)(?:\n\n|\n[a-z#])",
            source,
            re.S,
        )
        self.assertIsNotNone(invocation, "azure-result invocation not found")
        harness_args = sorted(
            re.findall(r"--([a-z][-a-z0-9]*)", invocation.group(1))
        )
        # Extract the argument names from the parser.
        p = release.parser()
        azure_result_parser = None
        for action in p._subparsers._actions:
            if hasattr(action, "_parser_class"):
                for name, subparser in action.choices.items():
                    if name == "azure-result":
                        azure_result_parser = subparser
                        break
        self.assertIsNotNone(azure_result_parser)
        parser_args = sorted(
            opt.lstrip("-")
            for action in azure_result_parser._actions
            for opt in action.option_strings
            if opt.startswith("--") and opt != "--help"
        )
        self.assertEqual(harness_args, parser_args)

    def test_workflow_candidate_invocation_matches_parser(self):
        workflow = (
            Path(release.__file__).resolve().parent.parent
            / ".github"
            / "workflows"
            / "freebsd15-release.yml"
        )
        source = workflow.read_text(encoding="utf-8")
        invocation = re.search(
            r"python3 scripts/freebsd15_release\.py candidate\b"
            r"(.*?)(?:\n          \{|\n\n)",
            source,
            re.S,
        )
        self.assertIsNotNone(invocation, "candidate invocation not found")
        workflow_args = sorted(
            re.findall(
                r"^\s+--([a-z][-a-z0-9]*)",
                invocation.group(1),
                re.M,
            )
        )
        parser_args = sorted(
            opt.lstrip("-")
            for action in release.parser()
            ._subparsers._actions[1]
            .choices["candidate"]
            ._actions
            for opt in action.option_strings
            if opt.startswith("--") and opt != "--help"
        )
        self.assertEqual(workflow_args, parser_args)
        self.assertIn("--qemu-info", invocation.group(1))

    def test_stage_script_passes_azure_results_for_gated_sets(self):
        """The mutation-free staging script binds exact Azure results."""
        stage = (
            Path(release.__file__).resolve().parent
            / "freebsd15_stage_release.sh"
        )
        source = stage.read_text(encoding="utf-8")
        self.assertIn("AZURE_RESULTS_DIR", source)
        self.assertIn("--azure-results", source)

    def test_stage_script_compares_within_the_combined_manifest(self):
        stage = (
            Path(release.__file__).resolve().parent
            / "freebsd15_stage_release.sh"
        )
        source = stage.read_text(encoding="utf-8")
        self.assertNotIn("BASELINE_CANDIDATES_DIR", source)
        self.assertNotIn("--baseline", source)
        self.assertIn(
            '--minimum-core-reduction-percent "$minimum_core_reduction"',
            source,
        )
        self.assertIn(
            '--candidate "$assets_dir/publish-manifest.json"',
            source,
        )

    def test_staging_and_publish_scripts_have_disjoint_responsibilities(self):
        scripts = Path(release.__file__).resolve().parent
        stage = scripts / "freebsd15_stage_release.sh"
        publish = scripts / "freebsd15_publish.sh"
        stage_source = stage.read_text(encoding="utf-8")
        publish_source = publish.read_text(encoding="utf-8")
        self.assertNotRegex(stage_source, r"\bgh\b")
        self.assertNotIn("freebsd15_publish.sh", stage_source)
        self.assertIn("freebsd15_release.py stage", stage_source)
        self.assertIn("freebsd15_release.py compare", stage_source)
        self.assertIn("validation evidence allowlist mismatch", stage_source)
        self.assertIn('gh release create "$RELEASE_TAG"', publish_source)
        self.assertIn('gh release upload "$RELEASE_TAG"', publish_source)
        self.assertIn('gh release edit "$RELEASE_TAG"', publish_source)
        self.assertIn('gh release download "$RELEASE_TAG"', publish_source)

    def test_workflow_validation_mode_cannot_reach_release_mutation(self):
        workflow = (
            Path(release.__file__).resolve().parent.parent
            / ".github"
            / "workflows"
            / "freebsd15-release.yml"
        )
        source = workflow.read_text(encoding="utf-8")
        stage_block = source.split("\n  stage:\n", 1)[1].split(
            "\n  publish:\n", 1
        )[0]
        publish_block = source.split("\n  publish:\n", 1)[1]
        self.assertRegex(
            source,
            r"validation_only:\n"
            r"(?:        .*\n)*?"
            r"        type: boolean\n"
            r"        required: true\n"
            r"        default: false",
        )
        self.assertIn('test "$RELEASE_SET" = zfs', source)
        self.assertIn("needs: [prepare, build, azure_acceptance]", stage_block)
        self.assertIn("environment: azurelinux4-release", source)
        self.assertIn("scripts/freebsd15_stage_release.sh", stage_block)
        self.assertIn("if: inputs.validation_only", stage_block)
        self.assertIn("freebsd15-validation-evidence-", stage_block)
        self.assertIn("path: ${{ env.STAGING_ROOT }}/evidence/", stage_block)
        self.assertIn("retention-days: 1", stage_block)
        self.assertNotIn("contents: write", stage_block)
        self.assertNotIn("freebsd15_publish.sh", stage_block)
        self.assertIn("inputs.validation_only == false", publish_block)
        self.assertIn("needs.stage.result == 'success'", publish_block)
        self.assertIn("contents: write", publish_block)
        self.assertIn("scripts/freebsd15_stage_release.sh", publish_block)
        self.assertIn("scripts/freebsd15_publish.sh", publish_block)

    def test_publish_script_requires_reviewed_ufs_date_and_exact_assets(self):
        publish = (
            Path(release.__file__).resolve().parent / "freebsd15_publish.sh"
        )
        source = publish.read_text(encoding="utf-8")
        self.assertNotIn("20260812", source)
        self.assertIn("explicit reviewed RELEASE_DATE", source)
        self.assertIn('--release-date "$RELEASE_DATE"', source)
        self.assertIn("for asset in assets", source)
        self.assertIn('gh release create "$RELEASE_TAG"', source)
        self.assertIn("--draft", source)
        self.assertIn("--latest=false", source)
        self.assertIn("git/matching-refs/tags/$RELEASE_TAG", source)
        self.assertNotIn("git/ref/tags/$RELEASE_TAG", source)
        self.assertIn("duplicate exact tag refs", source)
        self.assertIn('gh release download "$RELEASE_TAG"', source)
        self.assertIn("downloaded release allowlist mismatch", source)
        self.assertNotIn('gh release upload "$RELEASE_TAG" "$baseline_dir', source)
        self.assertNotIn("*.sha256", source)
        self.assertNotIn("*.packages.txt", source)


if __name__ == "__main__":
    unittest.main()
