import contextlib
import io
import json
import os
import shutil
import types
import unittest
from pathlib import Path

from scripts import freebsd15_release as release


def capture(handler, args) -> str:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        handler(args)
    return output.getvalue()


class FreeBSD15ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            Path.cwd()
            / ".scratch"
            / f"freebsd15-release-test-{os.getpid()}-{self._testMethodName}"
        )
        self.candidates = self.root / "candidates"
        self.azure_results = self.root / "azure-results"
        self.output = self.root / "output"
        self.notes = self.root / "notes.md"
        self.source_commit = "a" * 40
        self.release_date = "20260812"
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def package_file(self, key, directory, extra=(), drop=()):
        profile = release.VARIANTS[key]
        manifest = release.package_manifest(
            profile["filesystem"], profile["flavor"]
        )
        names = [
            name
            for name in (*manifest["required"], *manifest["library_roots"])
            if name not in drop
        ]
        names.extend(extra)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{key}.packages.txt"
        path.write_text(
            "".join(f"{name} 15.1 1024\n" for name in names),
            encoding="utf-8",
        )
        return path

    def qemu_info(self, key, directory, allocated_size):
        profile = release.VARIANTS[key]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{key}-qemu-info.json"
        path.write_text(
            json.dumps(
                {
                    "format": "qcow2",
                    "virtual-size": profile["virtual_size"],
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

    def make_candidate(
        self,
        key,
        allocated_size=900,
        compressed_size=900,
        package_extra=(),
        package_drop=(),
    ):
        profile = release.VARIANTS[key]
        directory = self.candidates / key
        directory.mkdir(parents=True, exist_ok=True)
        asset = directory / profile["asset_name"]
        asset.write_bytes(b"x" * compressed_size)
        release.candidate_command(
            types.SimpleNamespace(
                architecture=profile["architecture"],
                filesystem=profile["filesystem"],
                flavor=profile["flavor"],
                package_manifest=self.package_file(
                    key,
                    directory,
                    extra=package_extra,
                    drop=package_drop,
                ),
                asset=asset,
                validated_sha256=release.sha256(asset),
                virtual_size=profile["virtual_size"],
                qemu_info=self.qemu_info(key, directory, allocated_size),
                source_name=profile["source_name"],
                source_url=release.source_url(key),
                source_sha256=profile["source_sha256"],
                source_bytes=123456,
                source_commit=self.source_commit,
                qemu_version="QEMU emulator version 10.0.2",
                runner=profile["runner"],
                run_id="5001",
                run_attempt="7",
                output=directory / "candidate.json",
            )
        )
        return directory / "candidate.json"

    def make_azure_result(self, key, **overrides):
        candidate_path = self.candidates / key / "candidate.json"
        if not candidate_path.is_file():
            self.make_candidate(key)
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        profile = release.VARIANTS[key]
        document = {
            "schema": release.CANDIDATE_SCHEMA,
            "type": "zvmi-freebsd15-azure-acceptance",
            "variant": key,
            "architecture": profile["architecture"],
            "filesystem": profile["filesystem"],
            "flavor": profile["flavor"],
            "asset_name": profile["asset_name"],
            "source_commit": self.source_commit,
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
            "resource_group": "rg-zvmi-release",
            "contracts": list(release.azure_contracts("zfs")),
            "workflow": {"run_id": "5001", "run_attempt": "7"},
        }
        document.update(overrides)
        path = self.azure_results / key / "azure-result.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def make_release_inputs(
        self,
        full_allocated=1000,
        full_compressed=1000,
        core_allocated=900,
        core_compressed=900,
    ):
        for key in release.build_variants("zfs"):
            full = release.VARIANTS[key]["flavor"] == "full"
            self.make_candidate(
                key,
                allocated_size=full_allocated if full else core_allocated,
                compressed_size=full_compressed if full else core_compressed,
            )
            self.make_azure_result(key)

    def stage(self, minimum=release.CORE_MINIMUM_REDUCTION_PERCENT):
        release.stage_command(
            types.SimpleNamespace(
                release_set="zfs",
                candidates=self.candidates,
                source_commit=self.source_commit,
                release_tag=f"FreeBSD-15.1-{self.release_date}",
                release_date=self.release_date,
                azure_results=self.azure_results,
                minimum_core_reduction_percent=minimum,
                output=self.output,
                notes=self.notes,
            )
        )

    def test_active_release_is_exact_four_unqualified_zfs_assets(self):
        self.assertEqual(set(release.RELEASE_SETS), {"zfs"})
        variants = release.build_variants("zfs")
        self.assertEqual(
            variants,
            (
                "aarch64-zfs-full",
                "x86_64-zfs-full",
                "aarch64-zfs-core",
                "x86_64-zfs-core",
            ),
        )
        self.assertEqual(
            {release.VARIANTS[key]["asset_name"] for key in variants},
            {
                "FreeBSD-15.1-aarch64.qcow2",
                "FreeBSD-15.1-x86_64.qcow2",
                "FreeBSD-15.1-aarch64.core.qcow2",
                "FreeBSD-15.1-x86_64.core.qcow2",
            },
        )
        self.assertTrue(
            all(release.VARIANTS[key]["filesystem"] == "zfs" for key in variants)
        )
        self.assertFalse(
            any(".zfs" in release.VARIANTS[key]["asset_name"] for key in variants)
        )

    def test_release_identity_is_dated_unqualified_and_reserves_history(self):
        self.assertEqual(
            release.release_identity("zfs", self.release_date),
            (
                f"FreeBSD-15.1-{self.release_date}",
                f"FreeBSD 15.1 - {self.release_date}",
            ),
        )
        for date in (None, "", "20260230"):
            with self.subTest(date=date):
                with self.assertRaisesRegex(ValueError, "release date"):
                    release.release_identity("zfs", date)
        with self.assertRaisesRegex(ValueError, "historical full UFS"):
            release.release_identity("zfs", "20260724")
        self.assertIn("FreeBSD-15.1-zfs-20260729", release.RESERVED_RELEASE_TAGS)
        with self.assertRaises(ValueError):
            release.validate_release_tag(
                "zfs", "FreeBSD-15.1-zfs-20260729"
            )

    def test_matrix_and_describe_are_exactly_four(self):
        matrix = json.loads(
            capture(
                release.matrix_command,
                types.SimpleNamespace(release_set="zfs"),
            )
        )
        self.assertEqual(len(matrix["include"]), 4)
        self.assertEqual(
            [entry["variant"] for entry in matrix["include"]],
            list(release.build_variants("zfs")),
        )
        azure = json.loads(
            capture(
                release.azure_matrix_command,
                types.SimpleNamespace(release_set="zfs"),
            )
        )
        self.assertEqual(len(azure["include"]), 4)
        described = capture(
            release.describe_command,
            types.SimpleNamespace(
                release_set="zfs", release_date=self.release_date
            ),
        )
        self.assertIn(f"release_tag=FreeBSD-15.1-{self.release_date}", described)
        self.assertIn("asset_count=4", described)
        self.assertIn("core_minimum_reduction_percent=10", described)

    def test_zfs_core_profiles_share_matching_full_sources(self):
        for architecture in ("aarch64", "x86_64"):
            full = release.VARIANTS[f"{architecture}-zfs-full"]
            core = release.VARIANTS[f"{architecture}-zfs-core"]
            for field in ("source_name", "source_sha256", "virtual_size"):
                self.assertEqual(full[field], core[field])
            self.assertEqual(
                release.source_url(f"{architecture}-zfs-full"),
                release.source_url(f"{architecture}-zfs-core"),
            )

    def test_package_manifests_are_keyed_by_filesystem_and_flavor(self):
        self.assertEqual(release.PACKAGE_MANIFEST_REVISION, 3)
        for flavor in ("full", "core"):
            ufs = release.package_manifest("ufs", flavor)
            zfs = release.package_manifest("zfs", flavor)
            self.assertIn("FreeBSD-ufs", ufs["required"])
            self.assertNotIn("FreeBSD-zfs", ufs["required"])
            self.assertIn("FreeBSD-zfs", zfs["required"])
            self.assertNotIn("FreeBSD-ufs", zfs["required"])
        self.assertTrue(release.package_manifest("zfs", "core")["prunes"])
        self.assertFalse(release.package_manifest("zfs", "full")["prunes"])

    def test_package_verification_is_filesystem_aware(self):
        zfs_names = release.package_manifest("zfs", "core")["required"]
        release.verify_package_manifest(
            "zfs", "core", [{"name": name} for name in zfs_names]
        )
        with self.assertRaisesRegex(ValueError, "missing FreeBSD-zfs"):
            release.verify_package_manifest(
                "zfs",
                "core",
                [{"name": name} for name in zfs_names if name != "FreeBSD-zfs"],
            )
        ufs_names = release.package_manifest("ufs", "full")["required"]
        release.verify_package_manifest(
            "ufs", "full", [{"name": name} for name in ufs_names]
        )

    def test_candidate_records_filesystem_manifest_revision(self):
        path = self.make_candidate("aarch64-zfs-core")
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["packages"]["manifest_revision"],
            release.PACKAGE_MANIFEST_REVISION,
        )
        self.assertIn("FreeBSD-zfs", document["packages"]["names"])
        self.assertNotIn("FreeBSD-ufs", document["packages"]["names"])

    def test_zfs_candidate_rejects_wrong_filesystem_manifest(self):
        with self.assertRaisesRegex(ValueError, "missing FreeBSD-zfs"):
            self.make_candidate(
                "x86_64-zfs-core",
                package_drop=("FreeBSD-zfs",),
                package_extra=("FreeBSD-ufs",),
            )

    def test_stage_publishes_exact_four_assets_and_notes(self):
        self.make_release_inputs()
        self.stage()
        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["release_set"], "zfs")
        self.assertEqual(
            manifest["release_tag"], f"FreeBSD-15.1-{self.release_date}"
        )
        self.assertEqual(len(manifest["assets"]), 4)
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
        self.assertIn("same architecture-specific pinned source", notes)
        self.assertIn("FreeBSD-zfs", notes)
        self.assertNotIn("FreeBSD-ufs", notes)
        self.assertIn("zpool_reguid", notes)
        self.assertIn("every published release asset", notes)

    def test_stage_rejects_incomplete_or_unexpected_candidate_matrix(self):
        for key in release.build_variants("zfs")[:-1]:
            self.make_candidate(key)
        with self.assertRaisesRegex(ValueError, "expected 4 candidate"):
            self.stage()
        shutil.rmtree(self.candidates)
        for key in release.build_variants("zfs")[:-1]:
            self.make_candidate(key)
        self.make_candidate("x86_64-ufs-core")
        with self.assertRaisesRegex(ValueError, "incomplete or unexpected"):
            self.stage()

    def test_stage_requires_exact_four_bound_azure_results(self):
        self.make_release_inputs()
        (
            self.azure_results
            / "aarch64-zfs-core"
            / "azure-result.json"
        ).unlink()
        with self.assertRaisesRegex(ValueError, "expected 4 azure result"):
            self.stage()

        self.make_azure_result("aarch64-zfs-core")
        path = (
            self.azure_results
            / "x86_64-zfs-core"
            / "azure-result.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        document["qcow_sha256"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "QCOW SHA-256"):
            self.stage()

    def test_stage_rejects_unexpected_azure_variant(self):
        self.make_release_inputs()
        path = self.azure_results / "unexpected" / "azure-result.json"
        path.parent.mkdir(parents=True)
        document = json.loads(
            (
                self.azure_results
                / "x86_64-zfs-core"
                / "azure-result.json"
            ).read_text(encoding="utf-8")
        )
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "expected 4 azure result"):
            self.stage()

    def test_full_core_pairing_requires_exact_identity_and_source(self):
        self.make_release_inputs()
        self.stage()
        manifest = json.loads(
            (self.output / "publish-manifest.json").read_text(encoding="utf-8")
        )
        rows = release.full_core_rows(manifest)
        self.assertEqual(len(rows), 2)
        for full, core in rows:
            self.assertEqual(full["architecture"], core["architecture"])
            self.assertEqual(full["filesystem"], core["filesystem"])
            self.assertEqual(full["source"], core["source"])

        broken = json.loads(json.dumps(manifest))
        core = next(a for a in broken["assets"] if a["flavor"] == "core")
        core["source"]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "pinned sources differ"):
            release.full_core_rows(broken)

        broken = json.loads(json.dumps(manifest))
        core = next(a for a in broken["assets"] if a["flavor"] == "core")
        core["architecture"] = "x86_64"
        with self.assertRaisesRegex(ValueError, "identity is invalid"):
            release.full_core_rows(broken)

    def test_core_size_gate_accepts_exact_ten_percent_boundary(self):
        self.make_release_inputs(
            full_allocated=1000,
            full_compressed=1000,
            core_allocated=900,
            core_compressed=900,
        )
        self.stage()

    def test_core_size_gate_rejects_allocated_and_compressed_failures(self):
        for field in ("allocated", "compressed/download"):
            with self.subTest(field=field):
                shutil.rmtree(self.candidates, ignore_errors=True)
                shutil.rmtree(self.azure_results, ignore_errors=True)
                self.make_release_inputs(
                    core_allocated=901 if field == "allocated" else 900,
                    core_compressed=901 if field == "compressed/download" else 900,
                )
                with self.assertRaisesRegex(ValueError, field):
                    self.stage()

    def test_core_size_gate_rejects_virtual_size_regression(self):
        rows = [
            (
                {
                    "architecture": "aarch64",
                    "virtual_size": 1000,
                    "allocated_size": 1000,
                    "compressed_size": 1000,
                },
                {
                    "architecture": "aarch64",
                    "virtual_size": 1001,
                    "allocated_size": 900,
                    "compressed_size": 900,
                },
            ),
            (
                {
                    "architecture": "x86_64",
                    "virtual_size": 1000,
                    "allocated_size": 1000,
                    "compressed_size": 1000,
                },
                {
                    "architecture": "x86_64",
                    "virtual_size": 1000,
                    "allocated_size": 900,
                    "compressed_size": 900,
                },
            ),
        ]
        with self.assertRaisesRegex(ValueError, "virtual size regressed"):
            release.enforce_core_size_gate(rows, 10)

    def test_core_threshold_is_fail_closed(self):
        for threshold in (0, 100, True):
            with self.subTest(threshold=threshold):
                with self.assertRaisesRegex(ValueError, "from 1 to 99"):
                    release.require_reduction_percent(threshold)

    def test_compare_reports_zfs_pairs_for_both_architectures(self):
        self.make_release_inputs()
        self.stage()
        report = capture(
            release.compare_command,
            types.SimpleNamespace(
                candidate=self.output / "publish-manifest.json",
                output=None,
            ),
        )
        self.assertIn("| aarch64 |", report)
        self.assertIn("| x86_64 |", report)
        self.assertIn("| 1000 | 900 | 10.0%", report)

    def test_load_publish_manifest_rejects_filesystem_manifest_swap(self):
        self.make_release_inputs()
        self.stage()
        path = self.output / "publish-manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        core = next(a for a in document["assets"] if a["flavor"] == "core")
        core["package_manifest"]["names"].remove("FreeBSD-zfs")
        core["package_manifest"]["names"].append("FreeBSD-ufs")
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing FreeBSD-zfs"):
            release.load_publish_manifest(path)


if __name__ == "__main__":
    unittest.main()
