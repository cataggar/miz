from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "ubuntu2604-core-validation.yml"
)


class Ubuntu2604CoreWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW_PATH.read_text(encoding="utf-8")

    def job(self, name: str, following: str | None = None) -> str:
        section = self.source.split(f"\n  {name}:\n", 1)[1]
        if following is not None:
            section = section.split(f"\n  {following}:\n", 1)[0]
        return section

    def test_only_exact_core_keys_and_assets_are_accepted(self) -> None:
        for name, following in (
            ("build", "native_qemu"),
            ("native_qemu", "azure_acceptance"),
            ("azure_acceptance", "validate"),
        ):
            section = self.job(name, following)
            self.assertEqual(section.count("- key: x86_64-core"), 1)
            self.assertEqual(section.count("- key: aarch64-core"), 1)
            self.assertNotIn("- key: x86_64-full", section)
            self.assertNotIn("- key: aarch64-full", section)
            self.assertIn(
                "asset_name: Ubuntu-26.04-x86_64.core.qcow2",
                section,
            )
            self.assertIn(
                "asset_name: Ubuntu-26.04-aarch64.core.qcow2",
                section,
            )
        gate = self.job("validate")
        self.assertIn('"x86_64-core": "Ubuntu-26.04-x86_64.core.qcow2"', gate)
        self.assertIn('"aarch64-core": "Ubuntu-26.04-aarch64.core.qcow2"', gate)
        self.assertIn("core candidate asset set is not exact", gate)

    def test_complete_build_and_acceptance_matrices_are_required(self) -> None:
        gate = self.job("validate")
        self.assertIn(
            "needs: [prepare, build, native_qemu, azure_acceptance]",
            gate,
        )
        self.assertIn("needs.native_qemu.result == 'success'", gate)
        self.assertIn("needs.azure_acceptance.result == 'success'", gate)
        self.assertIn("len(candidate_docs) != 2", gate)
        self.assertIn("len(native_docs) != 2", gate)
        self.assertIn("len(azure_docs) != 2", gate)
        self.assertIn("core validation matrix is incomplete", gate)

    def test_workflow_is_validation_only(self) -> None:
        self.assertNotIn("\n  publish:\n", self.source)
        self.assertNotIn("scripts/ubuntu2604_publish.sh", self.source)
        self.assertNotIn("gh release", self.source)
        self.assertNotIn("RELEASE_TAG", self.source)
        self.assertNotIn("refs/tags/", self.source)
        self.assertNotIn("contents: write", self.source)
        self.assertNotIn("release create", self.source)
        self.assertNotIn("release upload", self.source)

    def test_candidate_reuse_is_exact_source_run_and_attempt_bound(self) -> None:
        prepare = self.job("prepare", "build")
        self.assertIn(
            '.path <<<"$run")" = ".github/workflows/ubuntu2604-core-validation.yml"',
            prepare,
        )
        self.assertIn("/attempts/$candidate_run_attempt/jobs", prepare)
        self.assertIn('jq --arg name "build/native $key"', prepare)
        self.assertIn(
            "ubuntu2604-core-candidate-$key-$commit-$candidate_run_attempt",
            prepare,
        )
        self.assertIn(".expired == false and .size_in_bytes > 0", prepare)
        self.assertIn(
            'git ls-remote origin "refs/heads/main"',
            prepare,
        )
        gate = self.job("validate")
        self.assertIn("candidate workflow attempt is not exact", gate)
        self.assertIn('"run_id": candidate_run_id', gate)
        self.assertIn('"run_attempt": candidate_run_attempt', gate)

    def test_permissions_and_protected_environments_are_least_privilege(self) -> None:
        header = self.source.split("\njobs:\n", 1)[0]
        self.assertIn("permissions:\n  actions: read\n  contents: read", header)
        self.assertEqual(self.source.count("environment: ubuntu2604-signing"), 1)
        self.assertEqual(self.source.count("environment: ubuntu2604-release"), 1)
        self.assertEqual(self.source.count("id-token: write"), 2)
        self.assertNotIn("packages: write", self.source)
        self.assertNotIn("security-events: write", self.source)
        self.assertIn(
            "repo:cataggar/vmiz:environment:ubuntu2604-signing",
            self.source,
        )
        self.assertIn(
            "repo:cataggar/vmiz:environment:ubuntu2604-release",
            self.source,
        )

    def test_core_build_and_acceptance_contracts_are_explicit(self) -> None:
        build = self.job("build", "native_qemu")
        self.assertIn("FLAVOR: core", build)
        self.assertIn("VIRTUAL_SIZE: 3758096384", build)
        self.assertIn('-Dubuntu2604-flavor="$FLAVOR"', build)
        self.assertIn("candidate virtual size is not exactly 3584 MiB", build)
        self.assertNotRegex(
            build,
            re.compile(
                r"libguestfs|guestfish|supermin|"
                r"\bvirt-(?!fw-vars\b|firmware\b)[a-z0-9-]+"
            ),
        )
        native = self.job("native_qemu", "azure_acceptance")
        self.assertIn('-Dubuntu2604-flavor="$FLAVOR"', native)
        self.assertIn("verify-native-result", native)
        azure = self.job("azure_acceptance", "validate")
        self.assertIn("FLAVOR: core", azure)
        self.assertIn("ubuntu2604_azure_acceptance.sh run", azure)

    def test_core_size_contract_is_aligned_across_builder_and_acceptance(self) -> None:
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        acceptance = (
            ROOT / "tests" / "ubuntu2604_acceptance.zig"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "const core_virtual_size: u64 = 3584 * 1024 * 1024;",
            builder,
        )
        self.assertIn(".virtual_size = 3584 * mib", acceptance)
        self.assertIn("VIRTUAL_SIZE: 3758096384", self.source)

    def test_artifacts_are_commit_attempt_and_digest_bound(self) -> None:
        for prefix in (
            "ubuntu2604-core-candidate-",
            "ubuntu2604-core-native-",
            "ubuntu2604-core-azure-",
            "ubuntu2604-core-validation-",
        ):
            self.assertIn(prefix, self.source)
        gate = self.job("validate")
        self.assertIn("candidate_sha256", gate)
        self.assertIn("candidate_manifest_sha256", gate)
        self.assertIn("native_result_sha256", gate)
        self.assertIn("azure_result_sha256", gate)
        self.assertIn("release.validate_native_result", gate)
        self.assertIn("release.validate_azure_result", gate)

    def test_cleanup_is_unconditional_and_failure_reporting(self) -> None:
        build = self.job("build", "native_qemu")
        self.assertIn("- name: Clean privileged build state\n        if: always()", build)
        self.assertIn("set -uo pipefail", build)
        self.assertIn('sudo rm -rf -- "$WORK_DIR" "$BUNDLE_DIR" || status=1', build)
        self.assertIn('exit "$status"', build)

        native = self.job("native_qemu", "azure_acceptance")
        self.assertIn(
            "- name: Remove candidate and local acceptance state\n        if: always()",
            native,
        )
        self.assertIn('rm -rf -- "$RESULT_DIR" || status=1', native)

        azure = self.job("azure_acceptance", "validate")
        self.assertIn(
            "- name: Refresh Azure OIDC credential for unconditional cleanup\n"
            "        if: always()",
            azure,
        )
        self.assertIn(
            "- name: Delete only ownership-tagged temporary Azure resources\n"
            "        if: always()",
            azure,
        )
        self.assertIn(
            "- name: Remove derived VHD and local credentials\n        if: always()",
            azure,
        )


if __name__ == "__main__":
    unittest.main()
