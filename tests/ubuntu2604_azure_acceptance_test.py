#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ubuntu2604_azure_acceptance.sh"
LIBRARY = ROOT / "scripts" / "ubuntu2604_azure_acceptance_lib.sh"


class UbuntuAzureAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = ROOT / "tests" / f".ubuntu2604-azure-{os.getpid()}"
        shutil.rmtree(self.scratch, ignore_errors=True)
        (self.scratch / "bin").mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def environment(self, key: str = "x86_64-full") -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.scratch / 'bin'}:{os.environ['PATH']}",
            "STATE_FILE": str(self.scratch / "state"),
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "4",
            "CANDIDATE_KEY": key,
        }

    def run_library(self, command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", f'source "$ACCEPTANCE_LIBRARY"; {command}'],
            cwd=ROOT,
            env={**os.environ, "ACCEPTANCE_LIBRARY": str(LIBRARY)},
            check=False,
            capture_output=True,
            text=True,
        )

    def write_az(self, tags: dict[str, str]) -> Path:
        az = self.scratch / "bin" / "az"
        az.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if args[:2] == ["group", "exists"]:
    print("true")
elif args[:2] == ["group", "show"]:
    print(json.dumps({"tags": json.loads(os.environ["MOCK_TAGS"])}))
elif args[:2] == ["group", "delete"]:
    Path(os.environ["DELETE_MARKER"]).write_text("deleted\\n")
else:
    raise SystemExit(f"unexpected az arguments: {args!r}")
""",
            encoding="utf-8",
        )
        az.chmod(0o755)
        marker = self.scratch / "deleted"
        os.environ["MOCK_TAGS"] = json.dumps(tags)
        os.environ["DELETE_MARKER"] = str(marker)
        return marker

    def test_cleanup_accepts_full_and_core_candidate_keys(self) -> None:
        for key in (
            "x86_64-full",
            "aarch64-full",
            "x86_64-core",
            "aarch64-core",
        ):
            with self.subTest(key=key):
                result = subprocess.run(
                    [str(SCRIPT), "cleanup"],
                    cwd=ROOT,
                    env=self.environment(key),
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleanup_rejects_unknown_candidate_key(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "cleanup"],
            cwd=ROOT,
            env=self.environment("riscv64-core"),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_extra_command_arguments(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "cleanup", "unexpected"],
            cwd=ROOT,
            env=self.environment(),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_candidate_identity_helper_requires_exact_flavor_asset_tuple(self) -> None:
        valid = {
            "x86_64-full": "Ubuntu-26.04-x86_64.qcow2",
            "aarch64-full": "Ubuntu-26.04-aarch64.qcow2",
            "x86_64-core": "Ubuntu-26.04-x86_64.core.qcow2",
            "aarch64-core": "Ubuntu-26.04-aarch64.core.qcow2",
        }
        for key, asset in valid.items():
            architecture, flavor = key.split("-")
            with self.subTest(key=key):
                result = self.run_library(
                    "ubuntu2604_validate_candidate_identity "
                    f"{key} {architecture} {flavor} {asset}"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                asset_result = self.run_library(
                    f"ubuntu2604_expected_asset {architecture} {flavor}"
                )
                self.assertEqual(asset_result.stdout.strip(), asset)

        for command in (
            "ubuntu2604_validate_candidate_identity "
            "x86_64-core x86_64 full Ubuntu-26.04-x86_64.core.qcow2",
            "ubuntu2604_validate_candidate_identity "
            "x86_64-core x86_64 core Ubuntu-26.04-x86_64.qcow2",
            "ubuntu2604_validate_candidate_identity "
            "riscv64-core riscv64 core Ubuntu-26.04-riscv64.core.qcow2",
        ):
            with self.subTest(command=command):
                self.assertNotEqual(self.run_library(command).returncode, 0)

    def test_curl_auth_header_is_private_bearer_header(self) -> None:
        header = self.scratch / "auth-header"
        token = "regression-token-not-a-secret"
        env = {
            **os.environ,
            "AUTH_HEADER": str(header),
            "AUTH_TOKEN": token,
            "ACCEPTANCE_LIBRARY": str(LIBRARY),
        }
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$ACCEPTANCE_LIBRARY"; '
                'write_bearer_header "$AUTH_TOKEN" "$AUTH_HEADER"',
            ],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertNotIn(token, result.stdout)
        self.assertNotIn(token, result.stderr)
        self.assertEqual(
            header.read_text(encoding="utf-8"),
            f"Authorization: Bearer {token}\n",
        )
        self.assertEqual(header.stat().st_mode & 0o777, 0o600)

        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('write_bearer_header "$token" "$auth_header"\n  token=', harness)
        self.assertIn('--header "@$auth_header"', harness)

    def test_conversion_attestation_binds_qemu_info_digest(self) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'qemu_info_sha256 = hashlib.sha256(open(info_path, "rb").read()).hexdigest()',
            harness,
        )
        self.assertIn('"qemu_info_sha256": qemu_info_sha256', harness)
        self.assertIn('--vhd-info "$RESULT_DIR/vhd-info.json"', harness)
        self.assertIn('--conversion-attestation "$conversion_attestation"', harness)
        self.assertNotIn("--vhd-current-size", harness)

    def test_core_contract_checks_are_explicit_and_full_checks_are_preserved(
        self,
    ) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        core = harness.split(
            'if [[ "$FLAVOR" == core ]]; then\n  readarray -t core_identity',
            1,
        )[1].split(
            '\nelse\n  ssh "${ssh_options[@]}" "$ssh_target" '
            "'/usr/bin/bash -s' <<'GUEST'",
            1,
        )[0]
        for required in (
            "/proc/1/exe -ef /sbin/vmizinit",
            "test -x /usr/sbin/azagent",
            "test -s /var/lib/azagent/provisioned",
            "ResourceDisk.Format",
            "DataDisk.Mount",
            "/var/lib/cloud",
            "/var/lib/waagent",
            "/var/log/azure",
            "test ! -d /run/systemd/system",
            "initial_machine_id",
            "initial_host_key_fingerprint",
            "initial_authorized_keys_sha256",
            "initial_sentinel_sha256",
        ):
            self.assertIn(required, core)
        self.assertNotIn("systemctl is-active", core)
        self.assertIn("/usr/sbin/sshd -D -e", harness)
        self.assertIn("read_core_sshd_pid", harness)
        self.assertIn("/usr/bin/kill -KILL", harness)
        self.assertIn("az vm extension list", harness)
        self.assertIn('test -z "${first_sector//0/}"', harness)
        self.assertIn(
            'python3 "$RELEASE_SCHEMA" verify-azure-result',
            harness,
        )
        self.assertIn('--contracts "$azure_contract_list"', harness)

        full = harness.split(
            '\nelse\n  ssh "${ssh_options[@]}" "$ssh_target" '
            "'/usr/bin/bash -s' <<'GUEST'",
            1,
        )[1].split("\nfi\n", 1)[0]
        self.assertIn("/proc/1/exe -ef /usr/lib/systemd/systemd", full)
        self.assertIn("cloud-init status --wait", full)
        self.assertIn("walinuxagent.service", full)

    def test_binder_probe_is_required_only_for_core_flavor(self) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'if [[ "$FLAVOR" == core ]]; then\n'
            "  if [[ -z ${BINDER_PROBE:-} ]]; then\n"
            "    echo \"::error::Core Azure acceptance requires a Binder "
            'device probe binary"',
            harness,
        )
        self.assertIn('[[ -x "$BINDER_PROBE" ]]', harness)
        self.assertIn("base64", harness)

    def test_core_binder_module_trust_checks_reject_dkms_and_anbox_evidence(
        self,
    ) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        module_block = harness.split(
            'if [[ "$flavor" == core ]]; then\n  module_info=', 1
        )[1].split("\nfi\nGUEST", 1)[0]
        self.assertIn("/usr/sbin/modinfo binder_linux", module_block)
        self.assertIn("/lib/modules/*/kernel/*", module_block)
        self.assertIn("*/updates/dkms/*", module_block)
        self.assertIn('test -n "$module_signer"', module_block)
        self.assertIn('test "$module_sig_id" = "PKCS#7"', module_block)
        self.assertIn("grep -iq anbox", module_block)
        self.assertIn("dkms status", module_block)
        self.assertIn("/sys/module/binder_linux/taint", module_block)
        self.assertIn('test -z "$module_taint"', module_block)
        self.assertIn(
            "binder_linux:.*(verification failed|taint)", module_block
        )

    def test_core_binderfs_and_device_usability_are_probed(self) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        binder_section = harness.split(
            'if [[ "$FLAVOR" == core ]]; then\n  binder_probe_remote=', 1
        )[1].split("\nfi\n\nif", 1)[0]
        self.assertIn("binder_probe_sha256=$(sha256sum", binder_section)
        self.assertIn("base64 -w0 \"$BINDER_PROBE\"", binder_section)
        self.assertIn("binder_probe_remote_sha256", binder_section)
        self.assertIn(
            'test "$binder_probe_remote_sha256" = "$binder_probe_sha256"',
            binder_section,
        )
        self.assertIn('binderfs_mount=/dev/binderfs', binder_section)
        self.assertIn(
            'test "$(findmnt -n -o FSTYPE "$binderfs_mount")" = binder',
            binder_section,
        )
        self.assertIn('test -c "$binderfs_mount/binder-control"', binder_section)
        for device in ("binder", "hwbinder", "vndbinder"):
            self.assertIn(device, binder_section)
        self.assertIn('sudo -n "$probe" version', binder_section)
        self.assertIn(
            'sudo -n "$probe" alloc "$binderfs_mount/binder-control"',
            binder_section,
        )
        self.assertIn("vmiz-acceptance-probe", binder_section)

    def test_binder_probe_binary_exists_and_targets_public_uapi_constants(
        self,
    ) -> None:
        probe = (ROOT / "tests" / "binder_probe.zig").read_text(encoding="utf-8")
        self.assertIn("const BINDER_VERSION: u32 = 0xc0046209;", probe)
        self.assertIn("const BINDER_CTL_ADD: u32 = 0xc1086201;", probe)
        self.assertIn("protocol_version", probe)
        self.assertNotIn("anbox", probe.lower())

    def test_cleanup_requires_exact_ownership_tags(self) -> None:
        env = self.environment()
        tags = {
            "vmiz-owner": "ubuntu2604-release",
            "vmiz-run-id": "123",
            "vmiz-run-attempt": "4",
            "vmiz-candidate": "x86_64-full",
        }
        marker = self.write_az(tags)
        env["MOCK_TAGS"] = json.dumps(tags)
        env["DELETE_MARKER"] = str(marker)
        Path(env["STATE_FILE"]).write_text(
            "vmiz-u2604-123-4-x86-64-full\n", encoding="utf-8"
        )
        subprocess.run(
            [str(SCRIPT), "cleanup"], cwd=ROOT, env=env, check=True
        )
        self.assertTrue(marker.is_file())

        marker.unlink()
        tags["vmiz-owner"] = "someone-else"
        env["MOCK_TAGS"] = json.dumps(tags)
        result = subprocess.run(
            [str(SCRIPT), "cleanup"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
