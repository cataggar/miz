from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "ubuntu2604-image-benchmark.yml"
)


class Ubuntu2604ImageBenchmarkWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW_PATH.read_text(encoding="utf-8")

    def section(self, start: str, end: str | None = None) -> str:
        value = self.source.split(start, 1)[1]
        return value.split(end, 1)[0] if end is not None else value

    def test_is_manual_main_only_native_arm_workflow(self) -> None:
        header = self.source.split("\njobs:\n", 1)[0]
        self.assertIn("workflow_dispatch:", header)
        self.assertNotIn("pull_request:", header)
        self.assertNotIn("push:", header)
        self.assertIn("github.ref == 'refs/heads/main'", self.source)
        self.assertIn("runs-on: ubuntu-24.04-arm", self.source)
        self.assertIn("timeout-minutes: 240", self.source)
        self.assertIn('test "$(uname -m)" = aarch64', self.source)

    def test_permissions_and_actions_are_minimal_and_pinned(self) -> None:
        header = self.source.split("\njobs:\n", 1)[0]
        self.assertIn("permissions:\n  contents: read", header)
        self.assertNotIn("id-token: write", self.source)
        self.assertNotIn("environment:", self.source)
        self.assertNotIn("secrets.", self.source)
        actions = re.findall(r"uses: ([^\s]+)", self.source)
        self.assertEqual(
            actions,
            [
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "cataggar/ghr/actions/install@7d8c3ef0886dd428a97727fce3b74909d6eace78",
                "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            ],
        )
        for action in actions:
            self.assertRegex(action.rsplit("@", 1)[1], r"^[0-9a-f]{40}$")

    def test_staging_uses_production_builder_and_verified_exact_inputs(self) -> None:
        stage = self.section(
            "- name: Stage verified publication inputs, exact locks, and warm debz cache",
            "- name: Run one warm-up and three measured builds without networking",
        )
        self.assertIn("generalized-ubuntu2604 --", stage)
        self.assertIn("-Doptimize=ReleaseSafe", stage)
        self.assertIn("-Dubuntu2604-arch=aarch64", stage)
        self.assertIn("-Dubuntu2604-flavor=baremetal", stage)
        self.assertIn('--debz-cache "$cache"', stage)
        self.assertIn('cache="$INPUT_ROOT/debz-cache"', stage)
        self.assertIn('debz_inputs="$INPUT_ROOT/debz-inputs"', stage)
        self.assertIn('--debz-input-dir "$debz_inputs"', stage)
        self.assertNotIn('mv "$cache"', stage)
        self.assertNotIn("--debz-lock-dir", stage)
        self.assertIn("debz-exact-lock-*-arm64.json", stage)
        self.assertIn("benchmark.verify_benchmark_cache", stage)
        self.assertIn("benchmark.verify_lock_set", stage)
        self.assertIn("ubuntu-26.04-server-cloudimg-arm64.img", stage)
        self.assertIn("SHA256SUMS.gpg", stage)

    def test_measured_protocol_is_offline_and_uses_warm_inputs(self) -> None:
        measured = self.section(
            "- name: Run one warm-up and three measured builds without networking",
            "- name: Record and enforce the production non-regression gate",
        )
        self.assertIn("/usr/bin/unshare --net --", measured)
        self.assertEqual(measured.count("/usr/bin/unshare --net --"), 1)
        self.assertIn("sudo -E /usr/bin/unshare --net --", measured)
        self.assertIn("scripts/ubuntu2604_image_benchmark.py", measured)
        self.assertIn('--debz-cache "$INPUT_ROOT/debz-cache"', measured)
        self.assertIn('--debz-input-dir "$INPUT_ROOT/debz-inputs"', measured)
        self.assertIn('--debz-lock-dir "$INPUT_ROOT/locks"', measured)
        self.assertNotIn("sudo -E python3 scripts/ubuntu2604_image_benchmark.py", measured)
        self.assertIn('--signing-key "$SIGNING_KEY"', measured)
        self.assertNotIn("--keep-images", measured)
        self.assertNotIn("--acceptance-command", measured)
        self.assertIn('NON_REGRESSION_CEILING_NS: "530000000000"', self.source)

    def test_disk_and_artifact_failure_evidence_are_explicit(self) -> None:
        self.assertIn('STAGING_MINIMUM_FREE_BYTES: "38654705664"', self.source)
        self.assertIn('MEASURED_MINIMUM_FREE_BYTES: "32212254720"', self.source)
        upload = self.section(
            "- name: Upload benchmark timing, provenance, and logs",
            "- name: Remove benchmark state and private material",
        )
        self.assertIn(
            "if: always() && steps.private-material-check.outcome == 'success'",
            upload,
        )
        self.assertIn("benchmark-status.json", upload)
        self.assertIn("benchmark-summary.json", upload)
        self.assertIn("run-*/evidence/", upload)
        self.assertIn("staging-build.log", self.source)
        self.assertIn("private material found in evidence", self.source)

    def test_test_signer_is_fixed_and_private_material_is_not_uploaded(self) -> None:
        identity = self.section(
            "- name: Prepare one fixed non-secret test identity",
            "- name: Warm Zig dependencies and verify the test signer",
        )
        self.assertIn(
            "tests/fixtures/ubuntu2604-local-signing/signing-key.pem",
            identity,
        )
        self.assertIn("install -m 0600", identity)
        self.assertIn("ssh-keygen -q -t ed25519", identity)
        self.assertIn(
            'TEST_CERTIFICATE_SHA256: '
            '"74556e6a0b540eb0ed5a49d9e75a003987447699df59f1d68456548c47dc8009"',
            self.source,
        )
        upload = self.section(
            "- name: Upload benchmark timing, provenance, and logs",
            "- name: Remove benchmark state and private material",
        )
        self.assertNotIn("SIGNING_ROOT", upload)
        self.assertNotIn("signing-key.pem", upload)


if __name__ == "__main__":
    unittest.main()
