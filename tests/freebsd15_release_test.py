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
        self.baseline = self.root / "full-ufs-baseline.json"
        self.source_commit = "a" * 40
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
        manifest = release.PACKAGE_MANIFESTS[release.VARIANTS[key]["flavor"]]
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
        allocated_size=800,
        compressed_size=None,
    ):
        expected = release.VARIANTS[key]
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True, exist_ok=True)
        asset = candidate_dir / expected["asset_name"]
        if compressed_size is None:
            asset.write_bytes(f"{key} candidate\n".encode())
        else:
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

    def write_full_ufs_baseline(
        self,
        compressed_sizes=None,
        allocated_sizes=None,
    ):
        compressed_sizes = compressed_sizes or {}
        allocated_sizes = allocated_sizes or {}
        assets = []
        for key in release.RELEASE_SETS["ufs"]["variants"]:
            expected = release.VARIANTS[key]
            architecture = expected["architecture"]
            compressed_size = compressed_sizes.get(architecture, 1000)
            allocated_size = allocated_sizes.get(architecture, 1000)
            assets.append(
                {
                    "variant": key,
                    "architecture": architecture,
                    "filesystem": "ufs",
                    "flavor": "full",
                    "asset_name": expected["asset_name"],
                    "bytes": compressed_size,
                    "compressed_size": compressed_size,
                    "allocated_size": allocated_size,
                    "virtual_size": expected["virtual_size"],
                    "sha256": "0" * 64,
                    "packages": 499,
                }
            )
        document = {
            "schema": release.CANDIDATE_SCHEMA,
            "type": "zvmi-freebsd15-release",
            "release_set": "ufs",
            "release_tag": release.RELEASE_SETS["ufs"]["release_tag"],
            "source_commit": self.source_commit,
            "assets": assets,
        }
        self.baseline.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.baseline

    def make_azure_result(self, key, source_commit=None, **overrides):
        candidate_path = self.make_candidate(key)
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        document = {
            "schema": release.CANDIDATE_SCHEMA,
            "type": "zvmi-freebsd15-azure-acceptance",
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
            "derived_vhd_bytes": 7_340_032,
            "status": "success",
            "location": "eastus2",
            "vm_size": "Standard_D2s_v5",
            "resource_group": "rg-zvmi-release",
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
        azure_results=...,
        baseline=...,
        minimum_core_reduction_percent=None,
    ):
        selected = release.RELEASE_SETS[release_set]
        if azure_results is ...:
            azure_results = self.azure_results if release_set == "zfs" else None
        if baseline is ...:
            baseline = (
                self.write_full_ufs_baseline()
                if release_set == "core"
                else None
            )
        release.stage_command(
            types.SimpleNamespace(
                release_set=release_set,
                candidates=self.candidates,
                source_commit=self.source_commit,
                release_tag=release_tag or selected["release_tag"],
                azure_results=azure_results,
                baseline=baseline,
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
            if release_set == "zfs":
                self.make_azure_result(key)
            else:
                self.make_candidate(key)
        self.stage(release_set)

    def test_stages_exact_two_asset_ufs_release(self):
        self.stage_set("ufs")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "ufs")
        self.assertEqual(manifest["release_tag"], "FreeBSD-15.1-20260724")
        self.assertEqual(
            {asset["asset_name"] for asset in manifest["assets"]},
            {"FreeBSD-15.1-aarch64.qcow2", "FreeBSD-15.1-x86_64.qcow2"},
        )
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "publish-manifest.json",
            },
        )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("No checksum sidecar assets are published.", notes)
        self.assertIn(self.source_commit, notes)

    def test_stages_exact_two_asset_zfs_release(self):
        self.stage_set("zfs")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "zfs")
        self.assertEqual(manifest["release_tag"], "FreeBSD-15.1-zfs-20260729")
        self.assertEqual(
            {asset["asset_name"] for asset in manifest["assets"]},
            {
                "FreeBSD-15.1-aarch64.zfs.qcow2",
                "FreeBSD-15.1-x86_64.zfs.qcow2",
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
                asset["azure"]["contracts"],
                list(release.AZURE_CONTRACTS),
            )
        # The staging tree is the publish allowlist, so nothing but the two
        # assets and the manifest may appear in it.
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {
                "FreeBSD-15.1-aarch64.zfs.qcow2",
                "FreeBSD-15.1-x86_64.zfs.qcow2",
                "publish-manifest.json",
            },
        )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("ZFS-root", notes)
        self.assertIn("zpool_reguid", notes)
        self.assertIn("Exact-candidate matching-architecture Gen2 validation", notes)
        self.assertNotIn("does not claim exact-candidate Azure validation", notes)
        self.assertIn("No checksum sidecar assets are published.", notes)


    def test_azure_result_command_emits_valid_document(self):
        candidate_path = self.make_candidate("x86_64-zfs-full")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        asset = candidate_path.parent / candidate["asset_name"]
        output = self.root / "azure-result.json"
        vhd_sha256 = "f" * 64
        vhd_bytes = 8_388_608
        contracts = ",".join(release.AZURE_CONTRACTS)

        release.azure_result_command(
            types.SimpleNamespace(
                manifest=candidate_path,
                asset=asset,
                key="x86_64-zfs-full",
                source_commit=self.source_commit,
                vhd_sha256=vhd_sha256,
                vhd_bytes=vhd_bytes,
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
        self.assertEqual(document["type"], "zvmi-freebsd15-azure-acceptance")
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
                        vhd_bytes=1024,
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
                    vhd_bytes=1024,
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
                    vhd_bytes=1024,
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
                    vhd_bytes=1024,
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
                    vhd_bytes=1024,
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
                    vhd_bytes=1024,
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
        with self.assertRaisesRegex(ValueError, "expected 2 azure result"):
            self.stage("zfs")

    def test_zfs_stage_rejects_cross_variant_azure_result(self):
        self.make_azure_result("aarch64-zfs-full")
        self.make_azure_result("x86_64-zfs-full", variant="aarch64-zfs-full")
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
        self.make_azure_result("aarch64-zfs-full")
        self.make_azure_result(
            "x86_64-zfs-full",
            contracts=list(release.AZURE_CONTRACTS[:-1]),
        )
        with self.assertRaisesRegex(ValueError, "contracts"):
            self.stage("zfs")

    def test_ufs_stage_rejects_azure_results_argument(self):
        self.stage_set("ufs")
        with self.assertRaisesRegex(ValueError, "not applicable"):
            self.stage("ufs", azure_results=self.azure_results)

    def test_core_stage_rejects_azure_results_argument(self):
        self.stage_set("core")
        with self.assertRaisesRegex(ValueError, "not applicable"):
            self.stage("core", azure_results=self.azure_results)

    def test_rejects_incomplete_matrix(self):
        self.make_candidate("aarch64-zfs-full")
        with self.assertRaisesRegex(ValueError, "expected 2 candidate manifests"):
            self.stage("zfs")

    def test_rejects_candidates_from_another_release_set(self):
        self.make_candidate("aarch64-zfs-full")
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
        self.make_candidate("aarch64-zfs-full")
        self.make_candidate("x86_64-zfs-full", source_commit="b" * 40)
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
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        manifest_path = self.candidates / "aarch64-ufs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        del document["allocated_size"]
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "allocated size"):
            self.stage("core")

    def test_stage_rejects_tampered_allocated_size(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        manifest_path = self.candidates / "x86_64-ufs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["allocated_size"] += 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "qemu-img size metadata mismatch"):
            self.stage("core")

    def test_stage_rejects_tampered_qemu_info_input(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        manifest_path = self.candidates / "aarch64-ufs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        qemu_info = manifest_path.parent / document["validation"]["qemu_info"]["name"]
        qemu_document = json.loads(qemu_info.read_text(encoding="utf-8"))
        qemu_document["actual-size"] += 1
        qemu_info.write_text(json.dumps(qemu_document), encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError,
            "qemu-img validation input mismatch",
        ):
            self.stage("core")

    def test_stage_rejects_legacy_candidate_schema(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        manifest_path = self.candidates / "aarch64-ufs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["schema"] = release.CANDIDATE_SCHEMA - 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            self.stage("core")

    def test_candidate_rejects_a_cross_filesystem_asset_name(self):
        asset = self.root / release.VARIANTS["aarch64-ufs-full"]["asset_name"]
        asset.write_bytes(b"candidate\n")
        with self.assertRaisesRegex(ValueError, "asset must be"):
            release.candidate_command(
                self.candidate_arguments(
                    "aarch64-zfs-full",
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                )
            )

    def test_matrix_covers_release_assets_and_core_baselines(self):
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
                    expected_role = (
                        "release"
                        if entry["variant"] in selected["variants"]
                        else "baseline"
                    )
                    self.assertEqual(entry["release_role"], expected_role)

    def test_describe_reports_the_selected_release_set(self):
        output = capture(
            release.describe_command, types.SimpleNamespace(release_set="zfs")
        )
        self.assertIn("release_tag=FreeBSD-15.1-zfs-20260729\n", output)
        self.assertIn("release_title=FreeBSD 15.1 ZFS - 20260729\n", output)
        self.assertIn("asset_count=2\n", output)
        self.assertIn("core_minimum_reduction_percent=10\n", output)

    def test_release_sets_partition_every_variant_exactly_once(self):
        claimed = [
            key
            for selected in release.RELEASE_SETS.values()
            for key in selected["variants"]
        ]
        self.assertEqual(sorted(claimed), sorted(release.VARIANTS))
        tags = {
            selected["release_tag"] for selected in release.RELEASE_SETS.values()
        }
        self.assertEqual(len(tags), len(release.RELEASE_SETS))
        names = {variant["asset_name"] for variant in release.VARIANTS.values()}
        self.assertEqual(len(names), len(release.VARIANTS))

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
        self.assertEqual(len(profiles), len(release.VARIANTS))
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
            self.assertEqual(output, variant["asset_name"])
        self.assertEqual(seen, set(release.VARIANTS))

    def test_package_manifests_match_the_zig_manifest(self):
        source = MANIFEST_SOURCE.read_text(encoding="utf-8")
        required = re.findall(
            r'\.name = "([^"]+)",\s*\.source = \.\w+,', source
        )
        self.assertEqual(list(release.REQUIRED_PACKAGES), required)
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
        revisions = re.findall(r"\.revision = (\d+),", source)
        self.assertTrue(revisions)
        for revision in revisions:
            self.assertEqual(int(revision), release.PACKAGE_MANIFEST_REVISION)
        flavors = re.findall(r"pub fn parse.*?\}", source, re.S)[0]
        self.assertEqual(
            sorted(re.findall(r'"(\w+)"', flavors)),
            sorted(release.PACKAGE_MANIFESTS),
        )

    def test_retained_contract_covers_every_required_capability(self):
        # Each entry is a capability the issue's retain-at-minimum list names
        # and the package that must still deliver it in a core image.
        contract = {
            "UEFI boot": "FreeBSD-bootloader",
            "release kernel": "FreeBSD-kernel-generic",
            "virtio and Hyper-V": "FreeBSD-hyperv-tools",
            "rc": "FreeBSD-rc",
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
            "root growth": "FreeBSD-ufs",
        }
        for capability, package in contract.items():
            with self.subTest(capability=capability):
                self.assertIn(package, release.REQUIRED_PACKAGES)
                for flavor, manifest in release.PACKAGE_MANIFESTS.items():
                    self.assertIn(package, manifest["required"], flavor)
                    self.assertNotIn(package, manifest["excluded"], flavor)
                    with self.assertRaisesRegex(
                        ValueError, f"missing {package}"
                    ):
                        release.verify_package_manifest(
                            flavor,
                            [
                                {"name": name}
                                for name in release.REQUIRED_PACKAGES
                                if name != package
                            ],
                        )

    def test_verify_package_manifest_rejects_excluded_content(self):
        retained = [{"name": name} for name in release.REQUIRED_PACKAGES]
        release.verify_package_manifest("core", retained)
        for name in ("FreeBSD-clang", "FreeBSD-runtime-dbg", "FreeBSD-clibs-dev"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "still carries"):
                    release.verify_package_manifest(
                        "core", retained + [{"name": name}]
                    )
        # A third-party package that merely ends in an excluded class is not a
        # pkgbase family member, and the full flavor excludes nothing.
        release.verify_package_manifest("core", retained + [{"name": "py312-dev"}])
        release.verify_package_manifest(
            "full", retained + [{"name": "FreeBSD-clang"}]
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

    def test_stages_exact_two_asset_core_release(self):
        self.stage_set("core")

        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "core")
        self.assertEqual(manifest["release_tag"], "FreeBSD-15.1-core-20260730")
        self.assertEqual(
            {asset["asset_name"] for asset in manifest["assets"]},
            {
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
            },
        )
        self.assertEqual({asset["flavor"] for asset in manifest["assets"]}, {"core"})
        for asset in manifest["assets"]:
            self.assertEqual(asset["bytes"], asset["compressed_size"])
            self.assertGreater(asset["allocated_size"], 0)
            self.assertEqual(
                asset["virtual_size"],
                release.VARIANTS[asset["variant"]]["virtual_size"],
            )
        # No .sha256 or .packages.txt sidecar may reach the publish allowlist.
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
                "publish-manifest.json",
            },
        )
        notes = self.notes.read_text(encoding="utf-8")
        self.assertIn("not by deleting files from a full image", notes)
        self.assertIn("## Installed packages", notes)
        self.assertIn("FreeBSD-openssl-lib", notes)
        self.assertIn("No checksum sidecar assets are published.", notes)

    def test_core_stages_against_same_commit_validated_full_candidates(self):
        core_candidates = self.candidates
        baseline_candidates = self.root / "baseline-candidates"
        baseline_output = self.root / "baseline-output"
        baseline_notes = self.root / "baseline-notes.md"
        self.candidates = baseline_candidates
        try:
            for key in release.RELEASE_SETS["ufs"]["variants"]:
                self.make_candidate(
                    key,
                    allocated_size=1000,
                    compressed_size=1000,
                )
            release.stage_command(
                types.SimpleNamespace(
                    release_set="ufs",
                    candidates=baseline_candidates,
                    source_commit=self.source_commit,
                    release_tag=release.RELEASE_SETS["ufs"]["release_tag"],
                    azure_results=None,
                    baseline=None,
                    minimum_core_reduction_percent=(
                        release.CORE_MINIMUM_REDUCTION_PERCENT
                    ),
                    output=baseline_output,
                    notes=baseline_notes,
                )
            )
        finally:
            self.candidates = core_candidates
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(
                key,
                allocated_size=900,
                compressed_size=900,
            )
        self.stage(
            "core",
            baseline=baseline_output / "publish-manifest.json",
        )
        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [asset["variant"] for asset in manifest["assets"]],
            list(release.RELEASE_SETS["core"]["variants"]),
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
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        manifest_path = self.candidates / "x86_64-ufs-core" / "candidate.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["packages"]["names"].append("FreeBSD-tests")
        document["packages"]["count"] += 1
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "still carries FreeBSD-tests"):
            self.stage("core")

    def test_core_size_gate_accepts_the_threshold_boundary_for_both_architectures(
        self,
    ):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key, allocated_size=900, compressed_size=900)
        self.stage(
            "core",
            baseline=self.write_full_ufs_baseline(),
            minimum_core_reduction_percent=10,
        )
        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {asset["architecture"] for asset in manifest["assets"]},
            {"aarch64", "x86_64"},
        )

    def test_core_size_gate_rejects_a_regression_on_either_architecture(self):
        self.make_candidate(
            "aarch64-ufs-core",
            allocated_size=900,
            compressed_size=900,
        )
        self.make_candidate(
            "x86_64-ufs-core",
            allocated_size=901,
            compressed_size=900,
        )
        with self.assertRaisesRegex(
            ValueError,
            "x86_64 core allocated size reduction is below 10%",
        ):
            self.stage(
                "core",
                baseline=self.write_full_ufs_baseline(),
                minimum_core_reduction_percent=10,
            )

    def test_core_size_gate_rejects_compressed_size_regression(self):
        self.make_candidate(
            "aarch64-ufs-core",
            allocated_size=900,
            compressed_size=901,
        )
        self.make_candidate(
            "x86_64-ufs-core",
            allocated_size=900,
            compressed_size=900,
        )
        with self.assertRaisesRegex(
            ValueError,
            "aarch64 core compressed/download size reduction is below 10%",
        ):
            self.stage(
                "core",
                baseline=self.write_full_ufs_baseline(),
                minimum_core_reduction_percent=10,
            )

    def test_core_size_gate_honors_a_reviewed_threshold_override(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key, allocated_size=850, compressed_size=850)
        with self.assertRaisesRegex(ValueError, "below 20%"):
            self.stage(
                "core",
                baseline=self.write_full_ufs_baseline(),
                minimum_core_reduction_percent=20,
            )

    def test_core_size_gate_rejects_wrong_baseline_profile(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        mutations = {
            "flavor": ("flavor", "core"),
            "filesystem": ("filesystem", "zfs"),
            "architecture": ("architecture", "x86_64"),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                path = self.write_full_ufs_baseline()
                document = json.loads(path.read_text(encoding="utf-8"))
                document["assets"][0][field] = value
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "does not match profile"):
                    self.stage("core", baseline=path)

    def test_core_size_gate_requires_a_baseline(self):
        for key in release.RELEASE_SETS["core"]["variants"]:
            self.make_candidate(key)
        with self.assertRaisesRegex(ValueError, "require a full UFS --baseline"):
            self.stage("core", baseline=None)

    def test_compare_reports_all_sizes_for_both_architectures(self):
        self.stage_set("core")
        core_manifest = self.output / "publish-manifest.json"

        report = capture(
            release.compare_command,
            types.SimpleNamespace(
                baseline=self.baseline,
                candidate=core_manifest,
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
        self.assertIn("6477709312", report)
        self.assertEqual(
            (self.root / "comparison.md").read_text(encoding="utf-8"), report
        )

    def test_compare_refuses_a_reversed_full_core_comparison(self):
        self.stage_set("core")
        core_manifest = self.output / "publish-manifest.json"
        with self.assertRaisesRegex(ValueError, "baseline must be the full UFS"):
            release.compare_command(
                types.SimpleNamespace(
                    baseline=core_manifest,
                    candidate=self.baseline,
                    output=None,
                )
            )

    def test_compare_rejects_legacy_publish_schema(self):
        self.stage_set("core")
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))
        baseline["schema"] = release.CANDIDATE_SCHEMA - 1
        self.baseline.write_text(json.dumps(baseline), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            release.compare_command(
                types.SimpleNamespace(
                    baseline=self.baseline,
                    candidate=self.output / "publish-manifest.json",
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

    def test_publish_script_passes_azure_results_for_zfs(self):
        """Static assertion: freebsd15_publish.sh passes --azure-results for
        ZFS and validates AZURE_RESULTS_DIR only when needed."""
        publish = (
            Path(release.__file__).resolve().parent / "freebsd15_publish.sh"
        )
        source = publish.read_text(encoding="utf-8")
        self.assertIn("AZURE_RESULTS_DIR", source)
        self.assertIn("--azure-results", source)
        # The ZFS conditional must gate the env check.
        self.assertIn('RELEASE_SET" == "zfs"', source)

    def test_publish_script_builds_and_binds_trusted_core_baseline(self):
        publish = (
            Path(release.__file__).resolve().parent / "freebsd15_publish.sh"
        )
        source = publish.read_text(encoding="utf-8")
        self.assertIn("BASELINE_CANDIDATES_DIR", source)
        self.assertIn("--release-set ufs", source)
        self.assertIn('--candidates "$BASELINE_CANDIDATES_DIR"', source)
        self.assertIn('--source-commit "$SOURCE_COMMIT"', source)
        self.assertIn('--baseline "$baseline_dir/publish-manifest.json"', source)
        self.assertIn(
            '--minimum-core-reduction-percent "$minimum_core_reduction"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
