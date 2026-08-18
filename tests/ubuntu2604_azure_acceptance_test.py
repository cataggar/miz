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

    def test_only_two_full_candidates_are_accepted(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "cleanup"],
            cwd=ROOT,
            env=self.environment("x86_64-core"),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)

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
