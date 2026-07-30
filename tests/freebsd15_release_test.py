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
        self.source_commit = "a" * 40
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def candidate_arguments(self, key, **overrides):
        expected = release.VARIANTS[key]
        arguments = dict(
            architecture=expected["architecture"],
            filesystem=expected["filesystem"],
            flavor=expected["flavor"],
            package_manifest=self.package_manifest(key, self.root),
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
                package_manifest=self.package_manifest(key, candidate_dir),
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

    def test_compare_reports_the_core_download_size_reduction(self):
        self.stage_set("core")
        core_manifest = self.output / "publish-manifest.json"
        core = json.loads(core_manifest.read_text(encoding="utf-8"))
        # A synthetic baseline: only the recorded sizes matter to the report,
        # and building two real images is a maintainer step.
        baseline = {
            "schema": release.CANDIDATE_SCHEMA,
            "type": "zvmi-freebsd15-release",
            "release_set": "ufs",
            "release_tag": release.RELEASE_SETS["ufs"]["release_tag"],
            "assets": [
                {
                    "variant": key,
                    "architecture": release.VARIANTS[key]["architecture"],
                    "filesystem": release.VARIANTS[key]["filesystem"],
                    "flavor": "full",
                    "asset_name": release.VARIANTS[key]["asset_name"],
                    "bytes": 1000,
                    "sha256": "0" * 64,
                    "packages": 499,
                }
                for key in release.RELEASE_SETS["ufs"]["variants"]
            ],
        }
        for asset in core["assets"]:
            asset["bytes"] = 250
        baseline_path = self.root / "baseline.json"
        candidate_path = self.root / "candidate-set.json"
        baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
        candidate_path.write_text(json.dumps(core), encoding="utf-8")

        report = capture(
            release.compare_command,
            types.SimpleNamespace(
                baseline=baseline_path,
                candidate=candidate_path,
                output=self.root / "comparison.md",
            ),
        )
        self.assertIn("| 1000 | 250 | 75.0% | 499 |", report)
        self.assertIn("6477643776", report)
        self.assertEqual(
            (self.root / "comparison.md").read_text(encoding="utf-8"), report
        )

    def test_compare_refuses_to_compare_a_set_against_itself(self):
        self.stage_set("core")
        manifest_path = self.output / "publish-manifest.json"
        with self.assertRaisesRegex(ValueError, "two different flavors"):
            release.compare_command(
                types.SimpleNamespace(
                    baseline=manifest_path,
                    candidate=manifest_path,
                    output=None,
                )
            )


if __name__ == "__main__":
    unittest.main()
