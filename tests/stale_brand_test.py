from pathlib import Path
import re
import ssl
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_BRANDS = (b"v" + b"miz", b"z" + b"vmi")
ALLOWED_CONTENT_PATHS = {Path("doc/migration.md")}
ALLOWED_NON_CERTIFICATE_PEM_PATHS = {
    Path("tests/build_api_consumer/fixtures/registry-ca.pem"),
}
PEM_CERTIFICATE = re.compile(
    br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def encoded_brand_variants(brand: bytes) -> tuple[bytes, ...]:
    text = brand.decode("ascii")
    return tuple(
        text.encode(encoding)
        for encoding in (
            "ascii",
            "utf-16-be",
            "utf-16-le",
            "utf-32-be",
            "utf-32-le",
        )
    )


ENCODED_LEGACY_BRANDS = tuple(
    variant
    for brand in LEGACY_BRANDS
    for variant in encoded_brand_variants(brand)
)


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
            raw_contents = (ROOT / relative).read_bytes()
            contents = raw_contents.lower()
            for brand in LEGACY_BRANDS:
                offset = contents.find(brand)
                if offset >= 0:
                    line = contents.count(b"\n", 0, offset) + 1
                    violations.append(
                        f"{relative}:{line}: legacy brand in tracked content"
                    )

            if relative.suffix.lower() != ".pem":
                continue

            for certificate_index, pem in enumerate(
                PEM_CERTIFICATE.findall(raw_contents),
                start=1,
            ):
                try:
                    der = ssl.PEM_cert_to_DER_cert(
                        pem.decode("ascii")
                    )
                except (UnicodeDecodeError, ValueError) as error:
                    if relative in ALLOWED_NON_CERTIFICATE_PEM_PATHS:
                        continue
                    violations.append(
                        f"{relative}: certificate {certificate_index} "
                        f"cannot be decoded: {error}"
                    )
                    continue
                der = der.lower()
                for encoded_brand in ENCODED_LEGACY_BRANDS:
                    if encoded_brand.lower() in der:
                        violations.append(
                            f"{relative}: certificate {certificate_index} "
                            "contains legacy branding in DER metadata"
                        )
                        break

        self.assertEqual([], violations, "\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
