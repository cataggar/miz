from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_BRANDS = (b"v" + b"miz", b"z" + b"vmi")
ALLOWED_CONTENT_PATHS = {Path("doc/migration.md")}


class StaleBrandTests(unittest.TestCase):
    def test_tracked_tree_uses_only_the_canonical_brand(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.split(b"\0")

        violations: list[str] = []
        for raw_path in tracked:
            if not raw_path:
                continue
            relative = Path(raw_path.decode("utf-8"))
            lower_path = raw_path.lower()
            for brand in LEGACY_BRANDS:
                if brand in lower_path:
                    violations.append(
                        f"{relative}: legacy brand in tracked path"
                    )

            if relative in ALLOWED_CONTENT_PATHS:
                continue
            contents = (ROOT / relative).read_bytes().lower()
            for brand in LEGACY_BRANDS:
                offset = contents.find(brand)
                if offset >= 0:
                    line = contents.count(b"\n", 0, offset) + 1
                    violations.append(
                        f"{relative}:{line}: legacy brand in tracked content"
                    )

        self.assertEqual([], violations, "\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
