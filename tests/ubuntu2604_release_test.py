import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import tarfile
import types
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from scripts import ubuntu2604_release as release
from scripts.azure_vhd import MIZ_CREATOR_APPLICATION


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_DER = b"miz Ubuntu test certificate"
CERTIFICATE_SHA256 = hashlib.sha256(CERTIFICATE_DER).hexdigest()
SIGNING_CERTIFICATE_SHA256 = "4" * 64
OPERATION_ID = "00000000-0000-4000-8000-000000000001"
FORBIDDEN_PRODUCTION_TOOL = re.compile(
    r"libguestfs|guestfish|supermin|LIBGUESTFS_BACKEND_SETTINGS|"
    r"\bvirt-(?!fw-vars\b|firmware\b)[a-z0-9-]+"
)


def fixed_vhd_geometry(virtual_size: int) -> tuple[int, int, int]:
    total_sectors = min(virtual_size // 512, release.VHD_MAX_CHS_SECTORS)
    if total_sectors >= 65535 * 16 * 63:
        sectors_per_track = 255
        heads = 16
        cylinders_times_heads = total_sectors // sectors_per_track
    else:
        sectors_per_track = 17
        cylinders_times_heads = total_sectors // sectors_per_track
        heads = max((cylinders_times_heads + 1023) // 1024, 4)
        if cylinders_times_heads >= heads * 1024 or heads > 16:
            sectors_per_track = 31
            heads = 16
            cylinders_times_heads = total_sectors // sectors_per_track
        if cylinders_times_heads >= heads * 1024:
            sectors_per_track = 63
            heads = 16
            cylinders_times_heads = total_sectors // sectors_per_track
    return cylinders_times_heads // heads, heads, sectors_per_track


def fixed_vhd_footer(virtual_size: int) -> bytes:
    footer = bytearray(release.VHD_FOOTER_BYTES)
    footer[:8] = b"conectix"
    struct.pack_into(">II", footer, 8, 2, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    footer[28:32] = MIZ_CREATOR_APPLICATION
    struct.pack_into(">I", footer, 32, 0x00010000)
    struct.pack_into(">QQ", footer, 40, virtual_size, virtual_size)
    struct.pack_into(">HBB", footer, 56, *fixed_vhd_geometry(virtual_size))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


class Ubuntu2604ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            Path.cwd()
            / ".scratch"
            / f"ubuntu2604-release-{os.getpid()}-{self._testMethodName}"
        )
        self.candidates = self.root / "candidates"
        self.azure = self.root / "azure"
        self.source_commit = "a" * 40
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def android_smoke_provenance(
        self,
        architecture: str = "x86_64",
        *,
        runtime_sha256: str = "1" * 64,
        bundle_sha256: str = "2" * 64,
        config_sha256: str = "3" * 64,
    ) -> dict[str, object]:
        return {
            "schema": release.ANDROID_SMOKE_PROVENANCE_SCHEMA,
            "type": release.ANDROID_SMOKE_PROVENANCE_TYPE,
            "architecture": architecture,
            "producer_source_commit": "a" * 40,
            "android_immutable_reference": (
                f"registry.example.invalid/android@sha256:{'b' * 64}"
            ),
            "android_manifest_digest": "c" * 64,
            "runtime_sha256": runtime_sha256,
            "bundle_archive_sha256": bundle_sha256,
            "config_json_sha256": config_sha256,
        }

    def test_android_smoke_secret_is_exact_and_https(self):
        value = {
            "artifact_url": "https://artifacts.example.invalid/artifact.zip",
            "artifact_sha256": "9" * 64,
            "provenance_sha256": "0" * 64,
        }
        self.assertEqual(
            release.parse_android_smoke_secret(json.dumps(value)),
            value,
        )
        mutations = (
            {**value, "unexpected": "value"},
            {key: item for key, item in value.items() if key != "artifact_url"},
            {**value, "artifact_url": "http://artifacts.example.invalid/artifact.zip"},
            {
                **value,
                "artifact_url": "https://user@artifacts.example.invalid/artifact.zip",
            },
            {
                **value,
                "artifact_url": "https://artifacts.example.invalid:bad/artifact.zip",
            },
            {**value, "artifact_sha256": "F" * 64},
            {**value, "provenance_sha256": "F" * 64},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(SystemExit):
                    release.parse_android_smoke_secret(json.dumps(mutation))
        for malformed in ("", "[]", "{"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(SystemExit):
                    release.parse_android_smoke_secret(malformed)

    def test_android_smoke_provenance_is_exact_and_architecture_bound(self):
        self.assertEqual(
            release.ANDROID_SMOKE_PROVENANCE_SCHEMA,
            "android-smoke-provenance.v1",
        )
        self.assertEqual(
            release.ANDROID_SMOKE_PROVENANCE_TYPE,
            "application/vnd.android-smoke.v1+json",
        )
        value = self.android_smoke_provenance()
        self.assertEqual(
            release.parse_android_smoke_provenance(value, "x86_64"),
            {
                "runtime_sha256": "1" * 64,
                "bundle_sha256": "2" * 64,
                "config_sha256": "3" * 64,
            },
        )
        mutations = (
            {**value, "schema": 2},
            {**value, "type": "other"},
            {**value, "architecture": "aarch64"},
            {**value, "runtime_sha256": "F" * 64},
            {**value, "android_immutable_reference": "mutable:latest"},
            {**value, "android_manifest_digest": "F" * 64},
            {**value, "unexpected": "value"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(SystemExit):
                    release.parse_android_smoke_provenance(mutation, "x86_64")

    def test_prepare_android_smoke_inputs_verifies_and_exports_only_safe_values(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        runtime = inputs / "android-runtime"
        runtime.write_bytes(b"runtime fixture")
        config = b'{"mounts":[]}\n'
        bundle = inputs / "android-bundle.tar"
        with tarfile.open(bundle, "w") as archive:
            member = tarfile.TarInfo("config.json")
            member.size = len(config)
            archive.addfile(member, io.BytesIO(config))
        provenance = inputs / "provenance.json"
        provenance.write_text(
            json.dumps(
                self.android_smoke_provenance(
                    runtime_sha256=release.sha256(runtime),
                    bundle_sha256=release.sha256(bundle),
                    config_sha256=hashlib.sha256(config).hexdigest(),
                )
            ),
            encoding="utf-8",
        )
        artifact = inputs / "artifact.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.write(runtime, "android-runtime")
            archive.write(bundle, "android-bundle.tar")
            archive.write(provenance, "provenance.json")
        urls = {
            "https://artifacts.example.invalid/artifact.zip": artifact,
        }
        secret = {
            "artifact_url": next(iter(urls)),
            "artifact_sha256": release.sha256(artifact),
            "provenance_sha256": release.sha256(provenance),
        }
        downloads: list[str] = []

        def copy_download(url, destination, token, **_kwargs):
            downloads.append(url)
            shutil.copyfile(urls[url], destination)

        output_dir = self.root / "private-inputs"
        github_env = self.root / "github-env"
        args = types.SimpleNamespace(
            architecture="x86_64",
            output_dir=output_dir,
            github_env=github_env,
        )
        with mock.patch.dict(
            os.environ,
            {
                release.ANDROID_SMOKE_INPUT_ENV: json.dumps(secret),
                release.ANDROID_SMOKE_TOKEN_ENV: "fixture-token",
            },
            clear=False,
        ), mock.patch.object(
            release,
            "_download_private_https",
            side_effect=copy_download,
        ):
            release.prepare_android_smoke_inputs_command(args)

        self.assertEqual(downloads, [secret["artifact_url"]])
        self.assertFalse((output_dir / "artifact.zip").exists())
        exported = github_env.read_text(encoding="utf-8")
        self.assertIn(
            f"MIZ_UBUNTU2604_ANDROID_PROVENANCE_SHA256={release.sha256(provenance)}",
            exported,
        )
        self.assertIn(
            f"MIZ_UBUNTU2604_ANDROID_RUNTIME_SHA256={release.sha256(runtime)}",
            exported,
        )
        self.assertIn(
            f"MIZ_UBUNTU2604_ANDROID_BUNDLE_SHA256={release.sha256(bundle)}",
            exported,
        )
        for private in (
            *urls,
            "fixture-token",
            "producer_source_commit",
            "android_immutable_reference",
            "a" * 40,
            f"registry.example.invalid/android@sha256:{'b' * 64}",
        ):
            self.assertNotIn(private, exported)

    def test_prepare_android_smoke_inputs_checks_archive_digest_before_extraction(self):
        output_dir = self.root / "private-inputs"
        github_env = self.root / "github-env"
        secret = {
            "artifact_url": "https://artifacts.example.invalid/artifact.zip",
            "artifact_sha256": "0" * 64,
            "provenance_sha256": "0" * 64,
        }
        downloads: list[str] = []

        def write_bad_archive(url, destination, token, **_kwargs):
            downloads.append(url)
            destination.write_bytes(b"not the expected archive")

        args = types.SimpleNamespace(
            architecture="x86_64",
            output_dir=output_dir,
            github_env=github_env,
        )
        with mock.patch.dict(
            os.environ,
            {release.ANDROID_SMOKE_INPUT_ENV: json.dumps(secret)},
            clear=False,
        ), mock.patch.object(
            release,
            "_download_private_https",
            side_effect=write_bad_archive,
        ), mock.patch.object(release, "_extract_android_smoke_archive") as extract:
            with self.assertRaises(SystemExit):
                release.prepare_android_smoke_inputs_command(args)
        self.assertEqual(downloads, [secret["artifact_url"]])
        extract.assert_not_called()
        self.assertFalse(output_dir.exists())
        self.assertFalse(github_env.exists())

    def test_prepare_android_smoke_inputs_checks_provenance_digest_before_parsing(self):
        artifact = self.root / "artifact.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("android-runtime", b"runtime")
            archive.writestr("android-bundle.tar", b"bundle")
            archive.writestr("provenance.json", b"{}")
        secret = {
            "artifact_url": "https://artifacts.example.invalid/artifact.zip",
            "artifact_sha256": release.sha256(artifact),
            "provenance_sha256": "0" * 64,
        }
        output_dir = self.root / "private-inputs"
        github_env = self.root / "github-env"
        args = types.SimpleNamespace(
            architecture="x86_64",
            output_dir=output_dir,
            github_env=github_env,
        )

        def copy_archive(url, destination, token, **_kwargs):
            shutil.copyfile(artifact, destination)

        with mock.patch.dict(
            os.environ,
            {release.ANDROID_SMOKE_INPUT_ENV: json.dumps(secret)},
            clear=False,
        ), mock.patch.object(
            release,
            "_download_private_https",
            side_effect=copy_archive,
        ), mock.patch.object(release, "parse_android_smoke_provenance") as parse:
            with self.assertRaises(SystemExit):
                release.prepare_android_smoke_inputs_command(args)
        parse.assert_not_called()
        self.assertFalse(output_dir.exists())
        self.assertFalse(github_env.exists())

    def test_android_smoke_archive_rejects_nonexact_and_unsafe_members(self):
        normal = {
            "android-runtime": b"runtime",
            "android-bundle.tar": b"bundle",
            "provenance.json": b"provenance",
        }
        cases = {
            "missing": tuple(normal)[:-1],
            "extra": (*normal, "extra"),
            "traversal": (
                "../android-runtime",
                "android-bundle.tar",
                "provenance.json",
            ),
            "directory": (
                "android-runtime/",
                "android-bundle.tar",
                "provenance.json",
            ),
            "duplicate": (
                "android-runtime",
                "android-runtime",
                "android-bundle.tar",
                "provenance.json",
            ),
        }
        for label, names in cases.items():
            with self.subTest(label=label):
                archive_path = self.root / f"{label}.zip"
                output = self.root / f"{label}-output"
                output.mkdir()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        for name in names:
                            archive.writestr(name, normal.get(name, b"unsafe"))
                with self.assertRaises(SystemExit):
                    release._extract_android_smoke_archive(archive_path, output)
                self.assertEqual(list(output.iterdir()), [])

        for label, file_type in (
            ("symlink", stat.S_IFLNK),
            ("fifo", stat.S_IFIFO),
            ("directory-type", stat.S_IFDIR),
        ):
            with self.subTest(label=label):
                archive_path = self.root / f"{label}.zip"
                output = self.root / f"{label}-output"
                output.mkdir()
                with zipfile.ZipFile(archive_path, "w") as archive:
                    for name, data in normal.items():
                        member = zipfile.ZipInfo(name)
                        member.create_system = 3
                        member.external_attr = (
                            (
                                file_type
                                if name == "android-runtime"
                                else stat.S_IFREG
                            )
                            | 0o600
                        ) << 16
                        archive.writestr(member, data)
                with self.assertRaises(SystemExit):
                    release._extract_android_smoke_archive(archive_path, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_package_root_uses_native_mountless_ext4_round_trip(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        production = builder.split('test "profiles pin', 1)[0]
        self.assertIn(
            "miz.ext4_mountless.FileSystem.open",
            production,
        )
        self.assertIn("exportHostTree", production)
        self.assertIn("importHostTree", production)
        self.assertIn("native_root.finish()", production)
        self.assertIn("cloudimg-rootfs", production)
        self.assertNotIn("/dev/sda4", production)
        self.assertNotIn("/dev/sda3", production)
        for forbidden in (
            "virt-tar-out",
            "virt-tar-in",
            '"guestfish"',
            '"tar"',
            '"cp"',
        ):
            self.assertNotIn(forbidden, production)
        # The guest archive keyring is copied to a bounded, validated host copy
        # outside every debz staging/publication root via materializeTrustedKeyring,
        # and debz consumes the trusted copy's absolute path (not the guest path),
        # with a post-transaction check that the trusted bytes never changed.
        self.assertIn(
            "materializeTrustedKeyring(allocator, io, trusted_keyring, external_keyring)",
            production,
        )
        self.assertIn(
            "const absolute_keyring = trusted.path",
            production,
        )
        self.assertIn(
            "realPathFileAlloc(io, destination",
            production,
        )
        self.assertIn(
            "assertTrustedKeyringUnchanged",
            production,
        )
        self.assertNotIn(
            "realPathFileAlloc(io, trusted_keyring",
            production,
        )

    def test_mountless_round_trip_uses_indexed_bulk_paths(self):
        root_tree = (
            ROOT / "packages" / "miz" / "src" / "root_tree.zig"
        ).read_text(encoding="utf-8")
        ext4_mountless = (
            ROOT / "packages" / "miz" / "src" / "ext4_mountless.zig"
        ).read_text(encoding="utf-8")
        self.assertIn("path_index: std.StringHashMap(usize)", root_tree)
        self.assertIn("append_only_import = true", root_tree)
        self.assertIn("readFileAllocAt", ext4_mountless)

    def test_production_builder_is_fully_native_without_qemu_img(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        production = builder.split('test "profiles pin', 1)[0]
        self.assertIsNone(FORBIDDEN_PRODUCTION_TOOL.search(production))
        # Issue #476: the Ubuntu finalization emits the standalone compressed
        # release image natively, so qemu-img/qemu-utils no longer appear in
        # the production builder at all.
        self.assertEqual(production.count('"qemu-img"'), 0)
        self.assertEqual(production.count('"qemu-utils"'), 0)
        self.assertNotIn('"qemu-img", "convert"', production)
        self.assertIn(
            "miz.qcow2.writeStandaloneCompressed",
            production,
        )

    def test_arm64_uki_uses_normalized_efi_kernel_payload(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        production = builder.split('test "profiles pin', 1)[0]
        self.assertIn(
            "uki_kernel_payload.normalize(",
            production,
        )
        self.assertIn(
            ".linux = kernel_payload.bytes",
            production,
        )
        self.assertNotIn(
            ".linux = kernel_bytes",
            production,
        )

    def make_bundle(
        self,
        key: str,
        *,
        certificate_der: bytes = CERTIFICATE_DER,
        signing_certificate_sha256: str = SIGNING_CERTIFICATE_SHA256,
    ) -> None:
        architecture, flavor, asset_name = release.CANDIDATE_EXPECTED[key]
        candidate_dir = self.candidates / key
        candidate_dir.mkdir(parents=True)
        asset = candidate_dir / asset_name
        asset.write_bytes((key + "\n").encode())
        virtual_size = 2 * release.AZURE_VHD_ALIGNMENT
        provenance = candidate_dir / "internal-provenance"
        provenance.mkdir()
        source_architecture = "amd64" if architecture == "x86_64" else "arm64"
        prefix = f"ubuntu-26.04-server-cloudimg-{source_architecture}"
        artifact_digests = {
            "source_image": "5" * 64,
        }
        artifact_filenames = {
            "source_image": f"{prefix}.img",
            "image_manifest": f"{prefix}.manifest",
        }
        for name in ("image_manifest",):
            path = provenance / artifact_filenames[name]
            path.write_text(f"{name} for {key}\n", encoding="utf-8")
            artifact_digests[name] = release.sha256(path)
        checksum_lines = [
            f"{artifact_digests[name]}  {artifact_filenames[name]}"
            for name in artifact_filenames
        ]
        checksum_path = provenance / "SHA256SUMS"
        checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        signature_path = provenance / "SHA256SUMS.gpg"
        signature_path.write_bytes(b"detached signature")

        debz_transactions = []
        debz_packages = (
            release.CORE_DEBZ_PACKAGES
            if flavor == "core"
            else release.FULL_DEBZ_PACKAGES
        )
        for index, package in enumerate(debz_packages):
            lock_digest = format(7 + index, "x") * 64
            lock_path = (
                provenance
                / f"debz-exact-lock-{package}-{source_architecture}.json"
            )
            lock_path.write_text(
                json.dumps(
                    {
                        "schema": (
                            "https://debz.dev/schema/exact-closure-lock-v1"
                        ),
                        "version": 1,
                        "target_architecture": source_architecture,
                        "request_sha256": "1" * 64,
                        "policy_sha256": "2" * 64,
                        "repositories": [{"fixture": True}],
                        "packages": [
                            {
                                "name": "base-files",
                                "version": "1",
                                "architecture": source_architecture,
                                "retention": "retained",
                            },
                            {
                                "name": package,
                                "version": "1",
                                "architecture": source_architecture,
                                "retention": "requested",
                            },
                        ],
                        "digest_sha256": lock_digest,
                    }
                ),
                encoding="utf-8",
            )
            transaction_digest = chr(ord("a") + index) * 64
            transaction_path = (
                provenance
                / (
                    "debz-transaction-provenance-"
                    f"{package}-{source_architecture}.json"
                )
            )
            transaction_path.write_text(
                json.dumps(
                    {
                        "schema": (
                            "https://debz.dev/schema/transaction-result-v1"
                        ),
                        "version": 1,
                        "target_architecture": source_architecture,
                        "lock_sha256": lock_digest,
                        "outcome": "succeeded",
                        "final_verification": {"status": "exact_match"},
                        "digest_sha256": transaction_digest,
                    }
                ),
                encoding="utf-8",
            )
            debz_transactions.append(
                {
                    "package": package,
                    "exact_lock": {
                        "filename": lock_path.name,
                        "sha256": release.sha256(lock_path),
                        "digest_sha256": lock_digest,
                    },
                    "transaction_provenance": {
                        "filename": transaction_path.name,
                        "sha256": release.sha256(transaction_path),
                        "digest_sha256": transaction_digest,
                        "lock_sha256": lock_digest,
                    },
                }
            )
        provenance_document = {
            "schema": 1,
            "type": "miz-ubuntu2604-build-provenance",
            "architecture": architecture,
            "release": "26.04",
            "snapshot": {
                "id": "release-20260731",
                "base_url": (
                    "https://cloud-images.ubuntu.com/releases/"
                    "26.04/release-20260731/"
                ),
            },
            "canonical_key_fingerprint": "c" * 40,
            "sha256sums_signature_verified": True,
            "artifacts": {
                "sha256sums": {
                    "filename": "SHA256SUMS",
                    "sha256": release.sha256(checksum_path),
                },
                "sha256sums_signature": {
                    "filename": "SHA256SUMS.gpg",
                    "sha256": release.sha256(signature_path),
                },
                **{
                    name: {
                        "filename": filename,
                        "sha256": artifact_digests[name],
                    }
                    for name, filename in artifact_filenames.items()
                },
            },
            "debz": {
                "api_commit": release.DEBZ_API_COMMIT,
                "baseline": {
                    "source": (
                        "empty-debz-root"
                        if flavor == "core"
                        else "canonical-image-dpkg-status"
                    ),
                    "enforcement": "exact-final-closure",
                },
                "transactions": debz_transactions,
            },
        }
        if flavor == "core":
            provenance_document.update(
                {
                    "flavor": "core",
                    "virtual_size": virtual_size,
                    "minimum_root_free_bytes": 1024 * 1024,
                    "validated_root_free_bytes": 1024 * 1024,
                }
            )
            provenance_document["artifacts"]["source_image"]["role"] = (
                "signed-gpt-esp-substrate"
            )
            provenance_document["debz"]["package_roots"] = list(
                release.CORE_PACKAGE_ROOTS
            )
        (provenance / release.UBUNTU_PROVENANCE_FILENAME).write_text(
            json.dumps(provenance_document), encoding="utf-8"
        )
        certificate_sha256 = hashlib.sha256(certificate_der).hexdigest()
        fallback = (
            "EFI/BOOT/BOOTX64.EFI"
            if architecture == "x86_64"
            else "EFI/BOOT/BOOTAA64.EFI"
        )
        signing = {
            "schema": 1,
            "type": "miz-uki-signing",
            "architecture": architecture,
            "flavor": flavor,
            "signer_mode": "external-command",
            "certificate_sha256": certificate_sha256,
            "certificate_der_base64": base64.b64encode(certificate_der).decode(),
            "certificate_details": "subject=CN=miz Ubuntu test signer",
            "provider": {
                "name": "azure-artifact-signing",
                "endpoint": "https://wus.codesigning.azure.net",
                "account": "cataggar",
                "profile": "miz-uki",
                "signing_certificate_sha256": signing_certificate_sha256,
            },
            "signature_verification": "success",
            "files": [
                {
                    "path": fallback,
                    "unsigned_sha256": "2" * 64,
                    "signed_sha256": "3" * 64,
                    "finalized_sha256": "3" * 64,
                    "signed_bytes": 4096,
                    "signing_operation_id": OPERATION_ID,
                    "signing_certificate_sha256": signing_certificate_sha256,
                },
            ],
        }
        (provenance / f"uki-signing-{flavor}-{architecture}.json").write_text(
            json.dumps(signing), encoding="utf-8"
        )
        digest = release.sha256(asset)
        manifest = candidate_dir / "candidate.json"
        release.candidate_command(
            types.SimpleNamespace(
                key=key,
                architecture=architecture,
                flavor=flavor,
                asset=asset,
                validated_sha256=digest,
                virtual_size=virtual_size,
                source_commit=self.source_commit,
                provenance_dir=provenance,
                runner=f"ubuntu-{architecture}",
                run_id="100",
                run_attempt="1",
                output=manifest,
            )
        )

        azure_dir = self.azure / key
        azure_dir.mkdir(parents=True)
        vhd = azure_dir / "temporary.vhd"
        current_size = virtual_size
        with vhd.open("wb") as stream:
            stream.seek(current_size)
            stream.write(fixed_vhd_footer(current_size))
        vhd_info = azure_dir / "vhd-info.json"
        vhd_info.write_text(
            json.dumps({"format": "vpc", "virtual-size": current_size}),
            encoding="utf-8",
        )
        conversion = azure_dir / "conversion-attestation.json"
        conversion.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "type": "miz-azure-vhd-conversion",
                    "key": key,
                    "status": "success",
                    "tool": "miz",
                    "operation": "azure derive",
                    "source": {
                        "asset_name": asset_name,
                        "sha256_before": digest,
                        "sha256_after": digest,
                        "bytes": asset.stat().st_size,
                        "virtual_size": current_size,
                    },
                    "parameters": {
                        "input_sha256": digest,
                        "expected_virtual_size": current_size,
                        "output_format": "vpc-fixed",
                        "vhd_alignment_bytes": release.AZURE_VHD_ALIGNMENT,
                        "vhd_footer_bytes": release.VHD_FOOTER_BYTES,
                    },
                    "result": {
                        "sha256": release.sha256(vhd),
                        "bytes": vhd.stat().st_size,
                        "current_size": current_size,
                        "qemu_virtual_size": current_size,
                        "qemu_info_sha256": release.sha256(vhd_info),
                    },
                }
            ),
            encoding="utf-8",
        )
        settings = {
            "signatureTemplateNames": [
                "MicrosoftUefiCertificateAuthorityTemplate"
            ],
            "additionalSignatures": {
                "db": [
                    {
                        "type": "x509",
                        "value": [base64.b64encode(certificate_der).decode()],
                    }
                ]
            },
        }
        request = azure_dir / "request.json"
        response = azure_dir / "response.json"
        gallery = {"properties": {"securityProfile": {"uefiSettings": settings}}}
        request.write_text(json.dumps(gallery), encoding="utf-8")
        response.write_text(json.dumps(gallery), encoding="utf-8")
        release.azure_result_command(self.azure_result_args(key))

    def azure_result_args(self, key: str):
        _, flavor, asset_name = release.CANDIDATE_EXPECTED[key]
        candidate_dir = self.candidates / key
        azure_dir = self.azure / key
        android_smoke = (
            {
                "android_smoke_provenance_sha256": "5" * 64,
                "android_smoke_runtime_sha256": "6" * 64,
                "android_smoke_bundle_sha256": "7" * 64,
                "android_smoke_config_sha256": "8" * 64,
            }
            if flavor == "core"
            else {
                "android_smoke_provenance_sha256": None,
                "android_smoke_runtime_sha256": None,
                "android_smoke_bundle_sha256": None,
                "android_smoke_config_sha256": None,
            }
        )
        return types.SimpleNamespace(
            manifest=candidate_dir / "candidate.json",
            asset=candidate_dir / asset_name,
            vhd=azure_dir / "temporary.vhd",
            vhd_info=azure_dir / "vhd-info.json",
            conversion_attestation=azure_dir / "conversion-attestation.json",
            key=key,
            source_commit=self.source_commit,
            location="eastus2",
            vm_size="Standard_D2ds_v5",
            resource_group=f"ubuntu-{key}",
            image_version_id=(
                f"/subscriptions/test/gallery/ubuntu/{key}/versions/1.0.0"
            ),
            uefi_request=azure_dir / "request.json",
            uefi_response=azure_dir / "response.json",
            contracts=",".join(release.azure_contracts(flavor)),
            run_id="100",
            run_attempt="1",
            output=azure_dir / "azure-result.json",
            **android_smoke,
        )

    def make_all(self) -> None:
        for key in release.EXPECTED:
            self.make_bundle(key)

    def stage(self, release_tag: str = "Ubuntu-26.04-20260822"):
        output = self.root / "staged"
        notes = self.root / "release-notes.md"
        release.stage_command(
            types.SimpleNamespace(
                candidates=self.candidates,
                azure_results=self.azure,
                source_commit=self.source_commit,
                release_tag=release_tag,
                output=output,
                notes=notes,
            )
        )
        return output, notes

    def rewrite(self, path: Path, mutate) -> None:
        document = json.loads(path.read_text())
        mutate(document)
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_success_stages_exact_two_assets_and_release_metadata(self):
        self.make_all()
        output, notes = self.stage()
        manifest = json.loads((output / "publish-manifest.json").read_text())
        self.assertEqual(manifest["type"], "miz-ubuntu2604-release")
        self.assertEqual(manifest["source_commit"], self.source_commit)
        self.assertEqual(manifest["certificate_sha256"], CERTIFICATE_SHA256)
        self.assertEqual(
            manifest["signing_certificate_sha256"],
            SIGNING_CERTIFICATE_SHA256,
        )
        self.assertEqual(
            [asset["asset_name"] for asset in manifest["assets"]],
            [release.EXPECTED[key][2] for key in release.RELEASE_ORDER],
        )
        self.assertEqual(
            {path.name for path in output.glob("*.qcow2")},
            {value[2] for value in release.EXPECTED.values()},
        )
        text = notes.read_text()
        self.assertIn("Ubuntu Server 26.04", text)
        self.assertIn("No checksum sidecar assets are published", text)
        self.assertNotIn("core", text.lower())

    def test_candidate_and_azure_result_schemas_bind_published_bytes(self):
        self.make_bundle("x86_64-full")
        candidate = json.loads(
            (self.candidates / "x86_64-full" / "candidate.json").read_text()
        )
        azure = json.loads(
            (self.azure / "x86_64-full" / "azure-result.json").read_text()
        )
        self.assertEqual(candidate["type"], "ubuntu2604-candidate")
        self.assertEqual(azure["type"], "ubuntu2604-azure-acceptance")
        self.assertEqual(azure["qcow_sha256"], candidate["sha256"])
        self.assertEqual(azure["azure_accepted_sha256"], candidate["sha256"])
        self.assertEqual(
            azure["conversion"]["source"]["sha256_before"],
            candidate["sha256"],
        )
        self.assertEqual(
            azure["conversion"]["parameters"]["expected_virtual_size"],
            candidate["virtual_size"],
        )
        self.assertEqual(set(azure["contracts"]), release.AZURE_CONTRACTS)
        self.assertEqual(
            candidate["azure_contracts"],
            list(release.azure_contracts("full")),
        )

    def test_core_candidate_and_result_bind_flavor_metadata_and_contracts(self):
        key = "x86_64-core"
        self.make_bundle(key)
        candidate_dir = self.candidates / key
        candidate = json.loads(
            (candidate_dir / "candidate.json").read_text(encoding="utf-8")
        )
        result_path = self.azure / key / "azure-result.json"
        azure = release.validate_azure_result(
            candidate_dir / "candidate.json",
            candidate_dir / candidate["asset_name"],
            result_path,
            key=key,
            source_commit=self.source_commit,
        )
        self.assertEqual(candidate["flavor"], "core")
        self.assertEqual(
            candidate["asset_name"],
            "Ubuntu-26.04-x86_64.core.qcow2",
        )
        self.assertEqual(
            candidate["azure_contracts"],
            list(release.azure_contracts("core")),
        )
        for field in (
            "source_commit",
            "architecture",
            "flavor",
            "asset_name",
        ):
            self.assertEqual(azure[field], candidate[field])
        self.assertEqual(azure["qcow_sha256"], candidate["sha256"])
        self.assertEqual(
            azure["certificate_sha256"],
            candidate["uki_signing"]["certificate_sha256"],
        )
        self.assertEqual(
            azure["signing_certificate_sha256"],
            candidate["uki_signing"]["signing_certificate_sha256"],
        )
        self.assertEqual(
            azure["fallback_uki_sha256"],
            candidate["uki_signing"]["fallback_uki_sha256"],
        )
        self.assertEqual(azure["contracts"], candidate["azure_contracts"])

    def test_core_native_result_binds_candidate_identity_and_contracts(self):
        key = "aarch64-core"
        self.make_bundle(key)
        candidate_dir = self.candidates / key
        candidate = json.loads(
            (candidate_dir / "candidate.json").read_text(encoding="utf-8")
        )
        android_smoke = {
            "provenance_sha256": "5" * 64,
            "runtime_sha256": "6" * 64,
            "bundle_sha256": "7" * 64,
            "config_sha256": "8" * 64,
            "architecture": candidate["architecture"],
            "candidate_key": key,
        }
        native_path = candidate_dir / "native-result.json"
        native_path.write_text(
            json.dumps(
                {
                    "schema": 5,
                    "type": "ubuntu2604-local-secure-boot-acceptance",
                    "architecture": candidate["architecture"],
                    "flavor": candidate["flavor"],
                    "virtual_size": candidate["virtual_size"],
                    "candidate_sha256": candidate["sha256"],
                    "certificate_sha256": candidate["uki_signing"][
                        "certificate_sha256"
                    ],
                    "fallback_uki_sha256": candidate["uki_signing"][
                        "fallback_uki_sha256"
                    ],
                    "contracts": list(release.native_contracts("core")),
                    "android_smoke": android_smoke,
                }
            ),
            encoding="utf-8",
        )
        result = release.validate_native_result(
            candidate_dir / "candidate.json",
            candidate_dir / candidate["asset_name"],
            native_path,
            key=key,
            source_commit=self.source_commit,
        )
        self.assertEqual(result["architecture"], "aarch64")
        self.assertEqual(result["flavor"], "core")
        self.assertEqual(
            set(result["contracts"]),
            release.CORE_NATIVE_CONTRACTS,
        )
        self.assertEqual(result["android_smoke"], android_smoke)

        for field, replacement in (
            ("schema", 1),
            ("architecture", "x86_64"),
            ("virtual_size", candidate["virtual_size"] + 1),
            ("candidate_sha256", "0" * 64),
            ("contracts", list(release.native_contracts("full"))),
            ("android_smoke", {**android_smoke, "architecture": "x86_64"}),
            ("android_smoke", {**android_smoke, "candidate_key": "x86_64-core"}),
            ("android_smoke", {**android_smoke, "runtime_sha256": "F" * 64}),
        ):
            with self.subTest(field=field, replacement=replacement):
                document = json.loads(native_path.read_text(encoding="utf-8"))
                document[field] = replacement
                native_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    release.validate_native_result(
                        candidate_dir / "candidate.json",
                        candidate_dir / candidate["asset_name"],
                        native_path,
                        key=key,
                        source_commit=self.source_commit,
                    )
                document[field] = (
                    5
                    if field == "schema"
                    else candidate["architecture"]
                    if field == "architecture"
                    else candidate["virtual_size"]
                    if field == "virtual_size"
                    else candidate["sha256"]
                    if field == "candidate_sha256"
                    else android_smoke
                    if field == "android_smoke"
                    else list(release.native_contracts("core"))
                )
                native_path.write_text(json.dumps(document), encoding="utf-8")

    def test_core_native_contract_set_covers_appliance_acceptance(self):
        self.assertEqual(
            release.CORE_NATIVE_CONTRACTS,
            {
                "matching-architecture-native-kvm",
                "standalone-zstd-qcow2",
                "gpt-layout",
                "secure-boot",
                "uefi-db-signer",
                "signed-uki",
                "vtpm",
                "kernel-lockdown",
                "module-signatures",
                "tampered-uki-rejected",
                "key-only-ssh",
                "local-ovf-azagent-skip-ready",
                "azagent-provisioning",
                "mizinit-pid1",
                "mizinit-sshd-supervision",
                "sshd-restart",
                "persistent-provisioned-state",
                "no-cloud-init",
                "no-walinuxagent",
                "generalized-identity",
                "root-growth",
                "reboot-reconnect",
                "clean-service-health",
                "signed-binder-module",
                "binder-boot-required",
                "binderfs-dynamic-devices",
                "binder-device-usability",
                "android-smoke-artifact-provenance",
                "android-container-boot-completed",
                "android-container-abi-match",
                "android-smoke-graceful-stop",
            },
        )

    def test_full_azure_contract_set_is_unchanged(self):
        self.assertEqual(
            release.FULL_AZURE_CONTRACTS,
            {
                "matching-architecture-gen2",
                "trusted-launch",
                "secure-boot",
                "vtpm",
                "uefi-db-signer",
                "signed-uki",
                "kernel-lockdown",
                "module-signatures",
                "key-only-ssh",
                "cloud-init-provisioning",
                "agent-ready",
                "root-growth",
                "managed-data-disk",
                "reboot-reconnect",
                "runtime-release-identity",
            },
        )
        self.assertEqual(release.AZURE_CONTRACTS, release.FULL_AZURE_CONTRACTS)

    def test_azure_root_growth_uses_original_root_geometry(self):
        script = (ROOT / "scripts/ubuntu2604_azure_acceptance.sh").read_text()
        self.assertIn("x86_64) root_first_lba=2324480", script)
        self.assertIn("aarch64) root_first_lba=2099200", script)
        self.assertIn(
            "original_root_size=$(((last_usable_lba - root_first_lba + 1) "
            "* gpt_sector_size))",
            script,
        )
        self.assertIn(
            "minimum_grown_root_size=$((original_root_size + 1073741824))",
            script,
        )
        self.assertIn(
            'test "$root_size" -gt "$minimum_grown_root_size"',
            script,
        )
        self.assertNotIn(
            'test "$root_size" -gt $((original_size + 1073741824))',
            script,
        )
        source_disk_size = 5 * 1024 * 1024 * 1024
        expanded_disk_size = 7 * 1024 * 1024 * 1024
        sector_size = 512
        partition_array_sectors = 32

        def root_size(disk_size: int, first_lba: int) -> int:
            last_usable_lba = (
                disk_size // sector_size - 2 - partition_array_sectors
            )
            return (last_usable_lba - first_lba + 1) * sector_size

        for first_lba in (2324480, 2099200):
            original_root_size = root_size(source_disk_size, first_lba)
            maximum_grown_root_size = root_size(expanded_disk_size, first_lba)
            self.assertLess(
                maximum_grown_root_size,
                source_disk_size + 1024 * 1024 * 1024,
            )
            self.assertGreater(
                maximum_grown_root_size,
                original_root_size + 1024 * 1024 * 1024,
            )

    def test_azure_full_service_contract_matches_ubuntu_2604(self):
        script = (ROOT / "scripts/ubuntu2604_azure_acceptance.sh").read_text()
        self.assertIn("cloud-init-network.service", script)
        self.assertNotIn("cloud-init.service", script)
        self.assertIn(
            "check network-online systemctl is-active --quiet "
            "network-online.target",
            script,
        )
        self.assertNotIn("networkctl is-online", script)
        self.assertIn("FAIL %s (exit %s)", script)
        self.assertIn(
            "failed_units=$(systemctl --failed --no-legend --plain)",
            script,
        )
        self.assertIn("check no-failed-units test -z", script)
        self.assertIn(
            "check conventional-resource-disk-policy "
            "validate_conventional_resource_disk",
            script,
        )
        self.assertNotIn(
            "check conventional-resource-disk-not-mounted not_mountpoint /mnt",
            script,
        )
        self.assertIn(
            "instanceView.bootDiagnostics.serialConsoleLogBlobUri",
            script,
        )

    def test_core_azure_contract_set_covers_appliance_acceptance(self):
        self.assertEqual(
            release.CORE_AZURE_CONTRACTS,
            {
                "matching-architecture-gen2",
                "trusted-launch",
                "secure-boot",
                "vtpm",
                "uefi-db-signer",
                "signed-uki",
                "kernel-lockdown",
                "module-signatures",
                "key-only-ssh",
                "azagent-provisioning",
                "agent-ready",
                "mizinit-pid1",
                "pid1-supervised-sshd",
                "sshd-restart-reconnect",
                "identity-persistence",
                "root-growth",
                "resource-disk",
                "managed-data-disk-mount-only",
                "reboot-reconnect",
                "runtime-release-identity",
                "no-cloud-init",
                "no-walinuxagent",
                "no-systemd-service-manager",
                "binder-module-signed",
                "no-dkms-binder-module",
                "no-anbox-evidence",
                "binderfs-mounted",
                "binder-devices-usable",
                "android-smoke-provenance-bound",
                "android-container-boot-completed",
                "android-container-abi-matched",
                "android-container-graceful-stop",
            },
        )

    def test_azure_result_rejects_contracts_not_bound_to_core_candidate(self):
        key = "x86_64-core"
        self.make_bundle(key)
        result_path = self.azure / key / "azure-result.json"
        self.rewrite(
            result_path,
            lambda value: value.__setitem__(
                "contracts", list(release.azure_contracts("full"))
            ),
        )
        candidate_dir = self.candidates / key
        with self.assertRaises(SystemExit):
            release.validate_azure_result(
                candidate_dir / "candidate.json",
                candidate_dir / release.CANDIDATE_EXPECTED[key][2],
                result_path,
                key=key,
                source_commit=self.source_commit,
            )

    def test_core_azure_result_rejects_candidate_binding_changes(self):
        key = "x86_64-core"
        mutations = {
            "source_commit": "b" * 40,
            "architecture": "aarch64",
            "asset_name": "Ubuntu-26.04-aarch64.core.qcow2",
            "qcow_sha256": "0" * 64,
            "certificate_sha256": "1" * 64,
            "signing_certificate_sha256": "2" * 64,
            "fallback_uki_sha256": "9" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                shutil.rmtree(self.candidates / key, ignore_errors=True)
                shutil.rmtree(self.azure / key, ignore_errors=True)
                self.make_bundle(key)
                result_path = self.azure / key / "azure-result.json"
                self.rewrite(
                    result_path,
                    lambda value, field=field, replacement=replacement: (
                        value.__setitem__(field, replacement)
                    ),
                )
                candidate_dir = self.candidates / key
                with self.assertRaises(SystemExit):
                    release.validate_azure_result(
                        candidate_dir / "candidate.json",
                        candidate_dir / release.CANDIDATE_EXPECTED[key][2],
                        result_path,
                        key=key,
                        source_commit=self.source_commit,
                    )

    def test_core_azure_result_binds_android_smoke_provenance(self):
        key = "x86_64-core"
        self.make_bundle(key)
        result_path = self.azure / key / "azure-result.json"
        document = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], 2)
        self.assertEqual(
            document["android_smoke"],
            {
                "provenance_sha256": "5" * 64,
                "runtime_sha256": "6" * 64,
                "bundle_sha256": "7" * 64,
                "config_sha256": "8" * 64,
                "architecture": "x86_64",
                "candidate_key": key,
            },
        )
        candidate_dir = self.candidates / key
        result = release.validate_azure_result(
            candidate_dir / "candidate.json",
            candidate_dir / release.CANDIDATE_EXPECTED[key][2],
            result_path,
            key=key,
            source_commit=self.source_commit,
        )
        self.assertEqual(result["android_smoke"]["candidate_key"], key)
        document["schema"] = 1
        result_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            release.validate_azure_result(
                candidate_dir / "candidate.json",
                candidate_dir / release.CANDIDATE_EXPECTED[key][2],
                result_path,
                key=key,
                source_commit=self.source_commit,
            )

    def test_full_azure_result_never_carries_android_smoke_provenance(self):
        key = "x86_64-full"
        self.make_bundle(key)
        result_path = self.azure / key / "azure-result.json"
        document = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertNotIn("android_smoke", document)
        candidate_dir = self.candidates / key
        # Injecting android_smoke into a full-flavor result must be rejected:
        # the full azure result field set is exact and does not include it.
        self.rewrite(
            result_path,
            lambda value: value.__setitem__(
                "android_smoke",
                {
                    "provenance_sha256": "5" * 64,
                    "runtime_sha256": "6" * 64,
                    "bundle_sha256": "7" * 64,
                    "config_sha256": "8" * 64,
                    "architecture": "x86_64",
                    "candidate_key": key,
                },
            ),
        )
        with self.assertRaises(SystemExit):
            release.validate_azure_result(
                candidate_dir / "candidate.json",
                candidate_dir / release.CANDIDATE_EXPECTED[key][2],
                result_path,
                key=key,
                source_commit=self.source_commit,
            )

    def test_azure_result_command_rejects_android_smoke_args_for_full_flavor(self):
        key = "x86_64-full"
        self.make_bundle(key)
        args = self.azure_result_args(key)
        args.android_smoke_provenance_sha256 = "5" * 64
        with self.assertRaises(SystemExit):
            release.azure_result_command(args)

    def test_azure_result_command_requires_android_smoke_args_for_core_flavor(self):
        key = "x86_64-core"
        self.make_bundle(key)
        for field in (
            "android_smoke_provenance_sha256",
            "android_smoke_runtime_sha256",
            "android_smoke_bundle_sha256",
            "android_smoke_config_sha256",
        ):
            with self.subTest(field=field):
                args = self.azure_result_args(key)
                setattr(args, field, None)
                with self.assertRaises(SystemExit):
                    release.azure_result_command(args)

    def test_core_azure_result_rejects_android_smoke_provenance_mismatches(self):
        key = "x86_64-core"
        self.make_bundle(key)
        result_path = self.azure / key / "azure-result.json"
        candidate_dir = self.candidates / key
        mutations = {
            "provenance_sha256": "not-a-digest",
            "runtime_sha256": "F" * 64,
            "bundle_sha256": "not-a-digest",
            "architecture": "aarch64",
            "candidate_key": "aarch64-core",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                self.rewrite(
                    result_path,
                    lambda value, field=field, replacement=replacement: (
                        value["android_smoke"].__setitem__(field, replacement)
                    ),
                )
                with self.assertRaises(SystemExit):
                    release.validate_azure_result(
                        candidate_dir / "candidate.json",
                        candidate_dir / release.CANDIDATE_EXPECTED[key][2],
                        result_path,
                        key=key,
                        source_commit=self.source_commit,
                    )
                self.rewrite(
                    result_path,
                    lambda value, key=key: value["android_smoke"].update(
                        {
                            "provenance_sha256": "5" * 64,
                            "runtime_sha256": "6" * 64,
                            "bundle_sha256": "7" * 64,
                            "config_sha256": "8" * 64,
                            "architecture": "x86_64",
                            "candidate_key": key,
                        }
                    ),
                )

    def test_azure_result_command_rejects_noncanonical_contract_argument(self):
        key = "x86_64-core"
        self.make_bundle(key)
        args = self.azure_result_args(key)
        args.contracts = ",".join(release.azure_contracts("full"))
        with self.assertRaises(SystemExit):
            release.azure_result_command(args)

    def test_azure_contracts_reject_unknown_flavor(self):
        with self.assertRaises(SystemExit):
            release.azure_contracts("minimal")

    def test_candidate_rejects_validation_digest_mismatch(self):
        key = "x86_64-full"
        architecture, flavor, asset_name = release.EXPECTED[key]
        self.make_bundle(key)
        root = self.candidates / key
        with self.assertRaises(SystemExit):
            release.candidate_command(
                types.SimpleNamespace(
                    key=key,
                    architecture=architecture,
                    flavor=flavor,
                    asset=root / asset_name,
                    validated_sha256="0" * 64,
                    virtual_size=2 * release.AZURE_VHD_ALIGNMENT,
                    source_commit=self.source_commit,
                    provenance_dir=root / "internal-provenance",
                    runner="runner",
                    run_id="1",
                    run_attempt="1",
                    output=root / "rejected-candidate.json",
                )
            )

    def test_verify_rejects_tampered_candidate_bytes_and_size(self):
        self.make_bundle("x86_64-full")
        bundle = self.candidates / "x86_64-full"
        asset = bundle / release.EXPECTED["x86_64-full"][2]
        asset.write_bytes(b"tampered")
        with self.assertRaises(SystemExit):
            release.verify_candidate(bundle / "candidate.json", asset)

    def test_stage_rejects_missing_or_extra_candidate_documents(self):
        self.make_all()
        (self.candidates / "aarch64-full" / "candidate.json").unlink()
        with self.assertRaises(SystemExit):
            self.stage()
        shutil.rmtree(self.root / "staged", ignore_errors=True)
        self.make_bundle_after_reset("aarch64-full")
        extra = self.candidates / "unexpected"
        extra.mkdir()
        shutil.copy(
            self.candidates / "x86_64-full" / "candidate.json",
            extra / "candidate.json",
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_requires_exact_two_azure_results(self):
        self.make_all()
        (self.azure / "aarch64-full" / "azure-result.json").unlink()
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_does_not_expand_publication_to_core_assets(self):
        self.make_all()
        self.make_bundle("x86_64-core")
        with self.assertRaises(SystemExit):
            self.stage()
        self.assertEqual(set(release.EXPECTED), {"x86_64-full", "aarch64-full"})
        self.assertEqual(len(release.RELEASE_ORDER), 2)

    def test_stage_rejects_extra_qcow_and_checksum_sidecar(self):
        self.make_all()
        (self.candidates / "extra.qcow2").write_bytes(b"extra")
        with self.assertRaises(SystemExit):
            self.stage()
        (self.candidates / "extra.qcow2").unlink()
        (self.azure / "forbidden.sha256").write_text("0" * 64)
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_source_commit_and_identity_changes(self):
        self.make_all()
        path = self.candidates / "x86_64-full" / "candidate.json"
        self.rewrite(path, lambda value: value.__setitem__("source_commit", "b" * 40))
        with self.assertRaises(SystemExit):
            self.stage()
        self.rewrite(path, lambda value: value.__setitem__("source_commit", self.source_commit))
        self.rewrite(path, lambda value: value.__setitem__("asset_name", "other.qcow2"))
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_tampered_or_unbound_provenance(self):
        self.make_all()
        provenance = self.candidates / "x86_64-full" / "internal-provenance"
        (provenance / "ubuntu-26.04-server-cloudimg-amd64.manifest").write_text(
            "tampered", encoding="utf-8"
        )
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        (provenance / "unbound.log").write_text("new", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_ubuntu_provenance_requires_immutable_signed_snapshot_inputs(self):
        mutations = (
            lambda value: value["snapshot"].__setitem__(
                "base_url",
                "https://cloud-images.ubuntu.com/releases/26.04/current/",
            ),
            lambda value: value.__setitem__(
                "canonical_key_fingerprint", "not-a-fingerprint"
            ),
            lambda value: value.__setitem__(
                "sha256sums_signature_verified", False
            ),
            lambda value: value["artifacts"].pop("source_image"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_bundle("x86_64-full")
                root = (
                    self.candidates
                    / "x86_64-full"
                    / "internal-provenance"
                )
                path = root / release.UBUNTU_PROVENANCE_FILENAME
                self.rewrite(path, mutate)
                with self.assertRaises(SystemExit):
                    release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_binds_source_and_manifest_checksums(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        checksum = root / "SHA256SUMS"
        checksum.write_text(
            "\n".join(checksum.read_text().splitlines()[:-1]) + "\n",
            encoding="utf-8",
        )
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["artifacts"]["sha256sums"].__setitem__(
                "sha256", release.sha256(checksum)
            ),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_binds_debz_lock_and_transaction(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["transactions"][0][
                "transaction_provenance"
            ].__setitem__("lock_sha256", "0" * 64),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_requires_locked_baseline_for_both_architectures(self):
        for key, architecture in (
            ("x86_64-full", "x86_64"),
            ("aarch64-full", "aarch64"),
        ):
            with self.subTest(architecture=architecture):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_bundle(key)
                root = self.candidates / key / "internal-provenance"
                metadata = root / release.UBUNTU_PROVENANCE_FILENAME
                document = json.loads(metadata.read_text(encoding="utf-8"))
                transaction = document["debz"]["transactions"][0]
                lock_path = root / transaction["exact_lock"]["filename"]
                lock = json.loads(lock_path.read_text(encoding="utf-8"))
                lock["packages"] = [
                    entry
                    for entry in lock["packages"]
                    if entry.get("retention") != "retained"
                ]
                lock_path.write_text(json.dumps(lock), encoding="utf-8")
                transaction["exact_lock"]["sha256"] = release.sha256(lock_path)
                metadata.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    release.validate_ubuntu_provenance(root, architecture)

    def test_ubuntu_provenance_requires_explicit_baseline_contract(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["baseline"].__setitem__(
                "enforcement", "transaction-actions-only"
            ),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_ubuntu_provenance_requires_two_stably_ordered_debz_transactions(self):
        self.make_bundle("x86_64-full")
        root = self.candidates / "x86_64-full" / "internal-provenance"
        metadata = root / release.UBUNTU_PROVENANCE_FILENAME
        self.rewrite(
            metadata,
            lambda value: value["debz"]["transactions"].reverse(),
        )
        with self.assertRaises(SystemExit):
            release.validate_ubuntu_provenance(root, "x86_64")

    def test_core_ubuntu_provenance_matches_builder_contract(self):
        key = "aarch64-core"
        self.make_bundle(key)
        root = self.candidates / key / "internal-provenance"
        document = release.validate_ubuntu_provenance(
            root,
            "aarch64",
            "core",
            2 * release.AZURE_VHD_ALIGNMENT,
        )
        self.assertEqual(document["flavor"], "core")
        self.assertEqual(
            document["artifacts"]["source_image"]["role"],
            "signed-gpt-esp-substrate",
        )
        self.assertEqual(
            document["debz"]["package_roots"],
            list(release.CORE_PACKAGE_ROOTS),
        )
        self.assertEqual(
            [item["package"] for item in document["debz"]["transactions"]],
            list(release.CORE_DEBZ_PACKAGES),
        )

    def test_core_ubuntu_provenance_rejects_contract_changes(self):
        key = "x86_64-core"
        mutations = (
            lambda value: value.__setitem__("flavor", "full"),
            lambda value: value["artifacts"]["source_image"].__setitem__(
                "role", "root-filesystem"
            ),
            lambda value: value["debz"].__setitem__(
                "package_roots", list(reversed(release.CORE_PACKAGE_ROOTS))
            ),
            lambda value: value["debz"]["baseline"].__setitem__(
                "source", "canonical-image-dpkg-status"
            ),
            lambda value: value.__setitem__("validated_root_free_bytes", 0),
            lambda value: value.__setitem__(
                "virtual_size", 3 * release.AZURE_VHD_ALIGNMENT
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                shutil.rmtree(self.candidates / key, ignore_errors=True)
                shutil.rmtree(self.azure / key, ignore_errors=True)
                self.make_bundle(key)
                root = self.candidates / key / "internal-provenance"
                metadata = root / release.UBUNTU_PROVENANCE_FILENAME
                self.rewrite(metadata, mutate)
                with self.assertRaises(SystemExit):
                    release.validate_ubuntu_provenance(
                        root,
                        "x86_64",
                        "core",
                        2 * release.AZURE_VHD_ALIGNMENT,
                    )

    def make_bundle_after_reset(self, key: str) -> None:
        shutil.rmtree(self.candidates / key)
        shutil.rmtree(self.azure / key)
        self.make_bundle(key)

    def test_stage_rejects_pem_der_and_embedded_private_keys(self):
        payloads = (
            b"-----BEGIN PRIVATE KEY-----\nsecret\n",
            b"-----BEGIN DSA PRIVATE KEY-----\nsecret\n",
            b"\x30\x82\x00\x08\x02\x01\x00\x30\x00\x00\x00\x00",
            b"prefix\n\x30\x0c\x30\x07\x06\x03\x2a\x03\x04\x05\x00\x04\x01\x00",
            b"binary-prefix\0openssh-key-v1\0binary-private-key",
        )
        for index, payload in enumerate(payloads):
            with self.subTest(index=index):
                shutil.rmtree(self.root)
                self.root.mkdir(parents=True)
                self.make_all()
                path = (
                    self.candidates
                    / "x86_64-full"
                    / "internal-provenance"
                    / "ubuntu-26.04-server-cloudimg-amd64.manifest"
                )
                path.write_bytes(payload)
                with self.assertRaises(SystemExit):
                    self.stage()

    def test_stage_rejects_acceptance_digest_and_contract_changes(self):
        self.make_all()
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("azure_accepted_sha256", "0" * 64))
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        self.rewrite(path, lambda value: value["contracts"].pop())
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_acceptance_status_and_vhd_evidence_changes(self):
        self.make_all()
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("status", "failure"))
        with self.assertRaises(SystemExit):
            self.stage()
        self.make_bundle_after_reset("x86_64-full")
        self.rewrite(
            path,
            lambda value: value["conversion"]["result"].__setitem__(
                "current_size",
                value["conversion"]["result"]["current_size"]
                + release.AZURE_VHD_ALIGNMENT,
            )
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_azure_result_rejects_malformed_vhd_structure(self):
        self.make_bundle("x86_64-full")
        vhd = self.azure / "x86_64-full" / "temporary.vhd"
        with vhd.open("r+b") as stream:
            stream.seek(-release.VHD_FOOTER_BYTES, 2)
            stream.write(b"\0" * release.VHD_FOOTER_BYTES)
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_malformed_qemu_vhd_info(self):
        self.make_bundle("x86_64-full")
        info = self.azure / "x86_64-full" / "vhd-info.json"
        info.write_text(
            json.dumps({"format": "raw", "virtual-size": 2 * 1024**2}),
            encoding="utf-8",
        )
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_unrelated_structurally_valid_vhd(self):
        self.make_bundle("x86_64-full")
        vhd = self.azure / "x86_64-full" / "temporary.vhd"
        with vhd.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"unrelated")
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_azure_result_rejects_conversion_parameter_mismatch(self):
        self.make_bundle("x86_64-full")
        attestation = (
            self.azure / "x86_64-full" / "conversion-attestation.json"
        )
        self.rewrite(
            attestation,
            lambda value: value["parameters"].__setitem__(
                "input_sha256", "0" * 64
            ),
        )
        with self.assertRaises(SystemExit):
            release.azure_result_command(
                self.azure_result_args("x86_64-full")
            )

    def test_stage_rejects_mixed_uki_and_artifact_signing_identities(self):
        self.make_bundle("x86_64-full")
        self.make_bundle("aarch64-full", certificate_der=b"different certificate")
        with self.assertRaises(SystemExit):
            self.stage()
        shutil.rmtree(self.candidates / "aarch64-full")
        shutil.rmtree(self.azure / "aarch64-full")
        self.make_bundle(
            "aarch64-full", signing_certificate_sha256="5" * 64
        )
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_azure_signing_binding_change(self):
        self.make_all()
        path = self.azure / "aarch64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value.__setitem__("certificate_sha256", "0" * 64))
        with self.assertRaises(SystemExit):
            self.stage()

    def test_stage_rejects_invalid_release_tag(self):
        self.make_all()
        with self.assertRaises(SystemExit):
            self.stage("Ubuntu-26.04-latest")

    def test_failed_stage_is_transactional(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        notes = self.root / "release-notes.md"
        notes.write_text("existing notes\n", encoding="utf-8")
        path = self.azure / "x86_64-full" / "azure-result.json"
        self.rewrite(path, lambda value: value["contracts"].pop())
        with self.assertRaises(SystemExit):
            self.stage()
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(notes.read_text(), "existing notes\n")
        self.assertEqual(list(self.root.glob(".*.tmp-*")), [])

    def test_notes_commit_failure_rolls_back_staged_assets(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        notes = self.root / "release-notes.md"
        notes.write_text("existing notes\n", encoding="utf-8")
        with mock.patch.object(release.os, "replace", side_effect=OSError("failure")):
            with self.assertRaises(OSError):
                self.stage()
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(notes.read_text(), "existing notes\n")

    def test_stage_refuses_nonempty_destination(self):
        self.make_all()
        output = self.root / "staged"
        output.mkdir()
        (output / "do-not-replace").write_text("sentinel")
        with self.assertRaises(SystemExit):
            self.stage()
        self.assertTrue((output / "do-not-replace").is_file())

    def test_canonical_signature_verification_is_native_and_gnupg_free(self):
        builder = (
            ROOT / "scripts" / "build_generalized_ubuntu2604.zig"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "ubuntu2604-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('@embedFile("fixtures/canonical-ubuntu-cloud-image-key.asc")', builder)
        self.assertIn("verifyOpenPgpDetachedSignature", builder)
        self.assertIn("PKCS1v1_5Signature.concatVerify", builder)
        self.assertIn("NativeHttpsDownloader.init", builder)
        self.assertIn("artifact_pipeline.acquireVerified", builder)
        self.assertNotIn('"gpg"', builder)
        self.assertNotIn('"curl"', builder)
        self.assertNotIn("gnupg", workflow)
        self.assertNotIn("curl", workflow)
        self.assertNotIn("ukify", workflow)
        self.assertIn('test -f "$uki_stub"', workflow)

    def test_publisher_is_draft_first_allowlisted_and_fail_safe(self):
        script = (ROOT / "scripts" / "ubuntu2604_publish.sh").read_text()
        self.assertIn('test "$(wc -l <"$expected_file")" -eq 2', script)
        self.assertIn('"x86_64-full": "Ubuntu-26.04-x86_64.qcow2"', script)
        self.assertIn('"aarch64-full": "Ubuntu-26.04-aarch64.qcow2"', script)
        self.assertIn("--draft", script)
        self.assertIn("stale-asset-ids", script)
        self.assertIn("retaining $RELEASE_TAG as a draft", script)
        self.assertIn('gh release download "$RELEASE_TAG"', script)
        self.assertIn("downloaded digest mismatch", script)
        self.assertLess(
            script.index('gh release create "$RELEASE_TAG"'),
            script.index('gh release upload "$RELEASE_TAG"'),
        )
        self.assertLess(
            script.index("downloaded digest mismatch"),
            script.index('gh release edit "$RELEASE_TAG"', script.index("downloaded digest mismatch")),
        )


if __name__ == "__main__":
    unittest.main()
