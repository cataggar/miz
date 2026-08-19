from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ubuntu2604-release.yml"


class Ubuntu2604WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_exact_candidate_matrices(self) -> None:
        boundaries = {
            "build": "native_qemu",
            "native_qemu": "azure_acceptance",
            "azure_acceptance": "publish",
        }
        for name, following in boundaries.items():
            section = self.source.split(f"\n  {name}:\n", 1)[1].split(
                f"\n  {following}:\n", 1
            )[0]
            self.assertEqual(section.count("- key: x86_64-full"), 1)
            self.assertEqual(section.count("- key: aarch64-full"), 1)
            self.assertNotIn("-core", section)
            self.assertIn("asset_name: Ubuntu-26.04-x86_64.qcow2", section)
            self.assertIn("asset_name: Ubuntu-26.04-aarch64.qcow2", section)

    def test_reuse_is_attempt_job_and_artifact_bound(self) -> None:
        self.assertIn("/attempts/$candidate_run_attempt/jobs", self.source)
        self.assertIn('jq --arg name "build/native $key"', self.source)
        self.assertIn('.expired == false and .size_in_bytes > 0', self.source)
        self.assertIn(
            "ubuntu2604-candidate-$key-$commit-$candidate_run_attempt",
            self.source,
        )

    def test_release_is_fail_closed_across_all_three_matrices(self) -> None:
        publish = self.source.split("  publish:", 1)[1]
        self.assertIn("needs: [prepare, build, native_qemu, azure_acceptance]", publish)
        self.assertIn("needs.native_qemu.result == 'success'", publish)
        self.assertIn("needs.azure_acceptance.result == 'success'", publish)
        self.assertIn("scripts/ubuntu2604_publish.sh", publish)
        self.assertIn("did not receive exactly two results of each kind", publish)

    def test_protected_environments_and_oidc_are_explicit(self) -> None:
        self.assertEqual(self.source.count("environment: ubuntu2604-signing"), 1)
        self.assertEqual(self.source.count("environment: ubuntu2604-release"), 2)
        self.assertIn("id-token: write", self.source)
        self.assertIn(
            "repo:cataggar/vmiz:environment:ubuntu2604-signing",
            self.source,
        )
        self.assertIn(
            "repo:cataggar/vmiz:environment:ubuntu2604-release",
            self.source,
        )

    def test_image_builder_installs_embedded_debz_development_libraries(self) -> None:
        install = self.source.split(
            "- name: Install complete Ubuntu image-builder dependencies", 1
        )[1].split("- name: Build built-in Artifact Signing client", 1)[0]
        self.assertIn("liblzma-dev", install)
        self.assertIn("libzstd-dev", install)

    def test_build_log_pipeline_prepares_work_dir_and_propagates_failures(self) -> None:
        build = self.source.split(
            "- name: Build exact finalized Ubuntu QCOW2", 1
        )[1].split(
            "- name: Validate standalone zstd QCOW2 and exact 5 GiB size", 1
        )[0]
        pipefail = build.index("set -euo pipefail")
        mkdir = build.index('mkdir -p "$GITHUB_WORKSPACE/$WORK_DIR"')
        build_log = build.index('build_log="$GITHUB_WORKSPACE/$WORK_DIR/build.log"')
        tee = build.index('2>&1 | tee "$build_log"')
        self.assertLess(pipefail, tee)
        self.assertLess(mkdir, build_log)
        self.assertLess(build_log, tee)

    def test_native_acceptance_cannot_silently_skip(self) -> None:
        native = self.source.split("  native_qemu:", 1)[1].split(
            "  azure_acceptance:", 1
        )[0]
        self.assertIn("test -r /dev/kvm", native)
        self.assertIn("test -w /dev/kvm", native)
        self.assertIn("VMIZ_UBUNTU2604_IMAGE=", native)
        self.assertIn("test -s \"$VMIZ_UBUNTU2604_ACCEPTANCE_RESULT\"", native)
        self.assertIn("tampered-uki-rejected", native)


if __name__ == "__main__":
    unittest.main()
