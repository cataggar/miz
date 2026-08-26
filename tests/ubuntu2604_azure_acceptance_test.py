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
            '\nelse\n  ssh "${ssh_options[@]}" "$ssh_target" \\\n'
            '    "/usr/bin/bash -s -- \'$has_resource_disk\'" <<\'GUEST\'',
            1,
        )[0]
        for required in (
            "/proc/1/exe -ef /sbin/mizinit",
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
            '\nelse\n  ssh "${ssh_options[@]}" "$ssh_target" \\\n'
            '    "/usr/bin/bash -s -- \'$has_resource_disk\'" <<\'GUEST\'',
            1,
        )[1].split("\nfi\n", 1)[0]
        self.assertIn("/proc/1/exe -ef /usr/lib/systemd/systemd", full)
        self.assertIn("cloud-init status --wait", full)
        self.assertIn("walinuxagent.service", full)
        self.assertIn("validate_conventional_resource_disk", full)
        self.assertIn('mountpoint -q /mnt || return 1', full)
        self.assertIn('"$resource_disk" != "$root_disk"', full)
        self.assertIn("/mnt/*) return 1", full)
        self.assertNotIn(
            "conventional-resource-disk-not-mounted not_mountpoint /mnt",
            full,
        )

    def test_failure_diagnostics_do_not_persist_boot_diagnostic_sas_uris(
        self,
    ) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        diagnostics = harness.split(
            "collect_failure_diagnostics() {", 1
        )[1].split("\n}\n\ncleanup_on_exit()", 1)[0]
        self.assertIn(
            "instanceView.bootDiagnostics.serialConsoleLogBlobUri",
            diagnostics,
        )
        self.assertIn(
            "instanceView.bootDiagnostics.consoleScreenshotBlobUri",
            diagnostics,
        )
        self.assertIn('serial_console_uri=\n', diagnostics)
        self.assertIn('console_screenshot_uri=\n', diagnostics)
        self.assertIn('"serial_console_log": boot_log', diagnostics)
        self.assertNotIn("json.dump(serial_console_uri", diagnostics)
        self.assertNotIn("json.dump(console_screenshot_uri", diagnostics)

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

    def test_android_smoke_binds_public_provenance_without_private_identity(self) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("MIZ_UBUNTU2604_ANDROID_PROVENANCE_SHA256", harness)
        self.assertIn("--android-smoke-provenance-sha256", harness)
        self.assertIn(
            'android_config_json_file="$(dirname '
            '"$MIZ_UBUNTU2604_ANDROID_BUNDLE")/guest-config.json"',
            harness,
        )
        self.assertIn("provenance SHA-256", harness)
        self.assertIn("config SHA-256", harness)
        self.assertNotIn("--android-smoke-source-commit", harness)
        self.assertNotIn("source commit", harness)

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
        self.assertIn("miz-acceptance-probe", binder_section)

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
            "miz-owner": "ubuntu2604-release",
            "miz-run-id": "123",
            "miz-run-attempt": "4",
            "miz-candidate": "x86_64-full",
        }
        marker = self.write_az(tags)
        env["MOCK_TAGS"] = json.dumps(tags)
        env["DELETE_MARKER"] = str(marker)
        Path(env["STATE_FILE"]).write_text(
            "miz-u2604-123-4-x86-64-full\n", encoding="utf-8"
        )
        subprocess.run(
            [str(SCRIPT), "cleanup"], cwd=ROOT, env=env, check=True
        )
        self.assertTrue(marker.is_file())

        marker.unlink()
        tags["miz-owner"] = "someone-else"
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

    # Regression coverage for a code-review finding: the Android container
    # state query used to fall back to a synthetic `{"status":"stopped"}`
    # whenever the query itself failed
    # (`state $android_container_id 2>/dev/null || printf ...`), which could
    # turn a permission error, a transient SSH failure, or any other query
    # failure into a false confirmation and authorize `delete` on a
    # container that might still be running. These tests exercise the
    # actual generated remote command and the actual python3 status parser
    # embedded in the harness, so a regression that reintroduces any
    # success-shaped fallback fails them.
    def test_android_state_query_never_carries_a_synthetic_stopped_fallback(
        self,
    ) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "\"sudo -n '$android_runtime_remote' state $android_container_id"
            ' 2>/dev/null" \\',
            harness,
        )
        self.assertNotIn(
            "state $android_container_id 2>/dev/null || printf", harness
        )
        self.assertNotIn('printf \'{\\"status\\":\\"stopped\\"}\'', harness)

    def test_android_state_query_parser_never_reports_stopped_for_failed_or_malformed_output(
        self,
    ) -> None:
        harness = SCRIPT.read_text(encoding="utf-8")
        python_source = harness.split("python3 -c '", 1)[1].split(
            "' 2>/dev/null || true", 1
        )[0]
        self.assertIn('json.load(sys.stdin).get("status", "")', python_source)

        non_terminal_inputs = (
            "",  # the state query failed and produced no output at all
            "\n",  # whitespace-only output
            "not json",  # malformed output
            "{}",  # valid JSON missing the status field entirely
            '{"status":"running"}',
            '{"status":"created"}',
            '{"status":"paused"}',
            '{"status":"error"}',
            '{"status":"Stopped"}',  # case must match exactly
            '{"status":"stopped "}',  # trailing whitespace must not match
        )
        for stdin_text in non_terminal_inputs:
            with self.subTest(stdin=stdin_text):
                result = subprocess.run(
                    ["python3", "-c", python_source],
                    input=stdin_text,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                # Mirror bash's `$(...)` command substitution, which strips
                # only trailing newlines and nothing else, so this matches
                # exactly what `android_stop_container`'s `[[ "$status" ==
                # stopped ]]` comparison actually sees.
                self.assertNotEqual(result.stdout.rstrip("\n"), "stopped")

        confirmed = subprocess.run(
            ["python3", "-c", python_source],
            input='{"status":"stopped"}',
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(confirmed.stdout.rstrip("\n"), "stopped")


if __name__ == "__main__":
    unittest.main()
