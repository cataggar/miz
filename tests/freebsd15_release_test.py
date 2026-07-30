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
        self.source_commit = "a" * 40
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def candidate_arguments(self, key, **overrides):
        expected = release.VARIANTS[key]
        arguments = dict(
            architecture=expected["architecture"],
            filesystem=expected["filesystem"],
            asset=self.root / expected["asset_name"],
            validated_sha256="",
            virtual_size=expected["virtual_size"],
            source_name=expected["source_name"],
            source_url=release.source_url(key),
            source_sha256=expected["source_sha256"],
            source_bytes=123456789,
            source_commit=self.source_commit,
            qemu_version="QEMU emulator version 10.0.2",
            runner=expected["runner"],
            run_id="1",
            run_attempt="1",
            output=self.root / "candidate.json",
        )
        arguments.update(overrides)
        return types.SimpleNamespace(**arguments)

    def make_candidate(self, key, source_commit=None):
        expected = release.VARIANTS[key]
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True)
        asset = candidate_dir / expected["asset_name"]
        asset.write_bytes(f"{key} candidate\n".encode())
        release.candidate_command(
            self.candidate_arguments(
                key,
                asset=asset,
                validated_sha256=release.sha256(asset),
                source_commit=source_commit or self.source_commit,
                output=candidate_dir / "candidate.json",
            )
        )
        return candidate_dir / "candidate.json"

    def stage(self, release_set, release_tag=None):
        selected = release.RELEASE_SETS[release_set]
        release.stage_command(
            types.SimpleNamespace(
                release_set=release_set,
                candidates=self.candidates,
                source_commit=self.source_commit,
                release_tag=release_tag or selected["release_tag"],
                output=self.output,
                notes=self.notes,
            )
        )

    def stage_set(self, release_set):
        for key in release.RELEASE_SETS[release_set]["variants"]:
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
        self.assertIn("No checksum sidecar assets are published.", notes)

    def test_rejects_incomplete_matrix(self):
        self.make_candidate("aarch64-zfs")
        with self.assertRaisesRegex(ValueError, "expected 2 candidate manifests"):
            self.stage("zfs")

    def test_rejects_candidates_from_another_release_set(self):
        self.make_candidate("aarch64-zfs")
        self.make_candidate("x86_64-ufs")
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
            / "x86_64-zfs"
            / release.VARIANTS["x86_64-zfs"]["asset_name"]
        )
        changed.write_bytes(b"tampered candidate\n")
        with self.assertRaisesRegex(ValueError, "candidate (size|digest) mismatch"):
            self.stage("zfs")

    def test_rejects_mismatched_source_commit(self):
        self.make_candidate("aarch64-zfs")
        self.make_candidate("x86_64-zfs", source_commit="b" * 40)
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            self.stage("zfs")

    def test_candidate_rejects_unpinned_sources(self):
        key = "aarch64-zfs"
        asset = self.root / release.VARIANTS[key]["asset_name"]
        asset.write_bytes(b"candidate\n")
        digest = release.sha256(asset)

        cases = {
            "source SHA-256 does not match": {"source_sha256": "0" * 64},
            "source filename does not match": {
                "source_name": release.VARIANTS["aarch64-ufs"]["source_name"]
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

    def test_candidate_rejects_a_cross_filesystem_asset_name(self):
        asset = self.root / release.VARIANTS["aarch64-ufs"]["asset_name"]
        asset.write_bytes(b"candidate\n")
        with self.assertRaisesRegex(ValueError, "asset must be"):
            release.candidate_command(
                self.candidate_arguments(
                    "aarch64-zfs",
                    asset=asset,
                    validated_sha256=release.sha256(asset),
                )
            )

    def test_matrix_covers_only_the_selected_release_set(self):
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
                    list(selected["variants"]),
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

    def test_describe_reports_the_selected_release_set(self):
        output = capture(
            release.describe_command, types.SimpleNamespace(release_set="zfs")
        )
        self.assertIn("release_tag=FreeBSD-15.1-zfs-20260729\n", output)
        self.assertIn("release_title=FreeBSD 15.1 ZFS - 20260729\n", output)
        self.assertIn("asset_count=2\n", output)

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
            r"\.flavor = \.\w+,\s*"
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
            filesystem,
            source_name,
            url,
            digest,
            virtual_size,
            output,
        ) in profiles:
            key = release.variant_key(architecture, filesystem)
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


if __name__ == "__main__":
    unittest.main()
