from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ubuntu2604-release.yml"
FORBIDDEN_PRODUCTION_TOOL = re.compile(
    r"libguestfs|guestfish|supermin|LIBGUESTFS_BACKEND_SETTINGS|"
    r"\bvirt-(?!fw-vars\b|firmware\b)[a-z0-9-]+"
)


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

    def test_image_builder_installs_complete_native_dependencies(self) -> None:
        install = self.source.split(
            "- name: Install complete Ubuntu image-builder dependencies", 1
        )[1].split("- name: Build built-in Artifact Signing client", 1)[0]
        # Native vmiz UKI assembly replaces systemd-ukify and its builder
        # dependency stack (systemd-ukify, binutils, python3-pefile, and the
        # host linux-image-generic kernel), so none of them may be installed.
        for removed in (
            "systemd-ukify",
            "binutils",
            "python3-pefile",
            "linux-image-generic",
            "util-linux",
            "liblzma-dev",
            "libzstd-dev",
            "cpio",
            "xz-utils",
            " zstd",
            "qemu-utils",
            "qemu-img",
        ):
            self.assertNotIn(removed, install)
        apt_install = install.index(
            'sudo apt-get install -y --no-install-recommends "${packages[@]}"'
        )
        # The kernel and initrd are extracted from the guest image natively, so
        # the host /boot kernel and its chmod fixup are gone.
        self.assertNotIn("/boot/vmlinuz", install)
        # systemd-boot-efi supplies only the PE/COFF stub that the native
        # assembler appends the UKI sections onto; the arch-correct stub is the
        # sole external input and must be verified present after install.
        self.assertIn("systemd-boot-efi", install)
        self.assertIn("/usr/lib/systemd/boot/efi/linuxx64.efi.stub", install)
        self.assertIn("/usr/lib/systemd/boot/efi/linuxaa64.efi.stub", install)
        stub_check = install.index('test -f "$uki_stub"')
        self.assertLess(apt_install, stub_check)

        # The offline-root executor now builds its sandbox with direct Linux
        # syscalls, so the util-linux helper binaries must no longer be
        # installed or discovered here.
        for removed_tool in ("mount", "mknod", "chroot", "setsid", "timeout", "unshare"):
            self.assertNotIn(removed_tool, install)
        # Native UKI assembly replaces the ukify subprocess entirely; neither the
        # tool nor a command -v probe for it may remain in the builder step.
        self.assertNotIn("ukify", install)
        self.assertNotIn("command -v", install)
        # Native X.509/Authenticode signing and Secure Boot verification replace
        # the openssl and sbsigntool utilities, so they must no longer be
        # installed or discovered in the image-builder dependency step.
        for removed_signing_tool in ("openssl", "sbsigntool", "sbverify"):
            self.assertNotIn(removed_signing_tool, install)
        for forbidden in (
            "libguestfs",
            "guestfish",
            "supermin",
            "virt-customize",
            "virt-copy-in",
            "virt-copy-out",
            "virt-ls",
            "virt-cat",
            "sudo chmod 0666 /dev/kvm",
            "LIBGUESTFS_BACKEND_SETTINGS",
            "force_tcg",
        ):
            self.assertNotIn(forbidden, install)

    def test_privileged_build_outputs_are_cleaned_with_privilege(self) -> None:
        cleanup = self.source.split("- name: Clean privileged build state", 1)[1]
        cleanup = cleanup.split("\n  native_qemu:", 1)[0]
        self.assertIn(
            'sudo rm -rf -- "$WORK_DIR" "$BUNDLE_DIR"',
            cleanup,
        )
        self.assertNotIn('rm -rf -- "$BUNDLE_DIR"', cleanup)

    def test_forbidden_tools_are_confined_to_optional_oracle_jobs(self) -> None:
        jobs = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_]*):\n", self.source))
        covered_matches: list[re.Match[str]] = []
        publish = self.source.split("\n  publish:\n", 1)[1]
        for index, job in enumerate(jobs):
            end = jobs[index + 1].start() if index + 1 < len(jobs) else len(self.source)
            section = self.source[job.start() : end]
            matches = list(FORBIDDEN_PRODUCTION_TOOL.finditer(section))
            if not matches:
                continue
            name = job.group(1)
            self.assertTrue(
                name.startswith("optional_oracle_"),
                f"{name} contains a forbidden production tool",
            )
            self.assertIn("continue-on-error: true", section)
            self.assertNotIn("\n    outputs:", section)
            self.assertNotIn("actions/upload-artifact", section)
            self.assertNotIn("actions/download-artifact", section)
            publish_needs = publish.split("\n    if:", 1)[0]
            self.assertNotIn(name, publish_needs)
            self.assertNotIn(f"needs.{name}", publish)
            covered_matches.extend(matches)
        self.assertEqual(
            len(covered_matches),
            len(list(FORBIDDEN_PRODUCTION_TOOL.finditer(self.source))),
            "forbidden tools may appear only in explicitly optional oracle jobs",
        )
        self.assertIn("python3-virt-firmware", self.source)
        self.assertIn("virt-fw-vars", self.source)

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
        self.assertIn('sudo -E "$(command -v zig)" build', build)
        self.assertIn('sudo chown -R "$(id -u):$(id -g)"', build)

    def test_build_validates_qcow2_and_publishes_metadata_natively(self) -> None:
        build_job = self.source.split("\n  build:\n", 1)[1].split(
            "\n  native_qemu:\n", 1
        )[0]
        validate = build_job.split(
            "- name: Validate standalone zstd QCOW2 and exact 5 GiB size", 1
        )[1].split("- name:", 1)[0]
        # The build job emits and validates the release image entirely with
        # vmiz; qemu-img/qemu-utils must not appear anywhere in it (issue #476,
        # acceptance: Ubuntu build must not invoke qemu tooling).
        self.assertNotIn("qemu-img", build_job)
        self.assertNotIn("qemu-utils", build_job)
        self.assertIn('"$vmiz" check "$asset"', validate)
        self.assertIn('"$vmiz" info --output=json "$asset"', validate)
        self.assertIn('vmiz="$GITHUB_WORKSPACE/zig-out/bin/vmiz"', validate)
        # Native metadata is the publication input the candidate provenance
        # binds and the exactness gate parses.
        self.assertIn("image-info.json", validate)
        self.assertIn('data.get("compression-type") != "zstd"', validate)
        self.assertIn("candidate virtual size is not exactly 5 GiB", validate)
        self.assertIn("candidate has a backing file", validate)

    def test_native_acceptance_cannot_silently_skip(self) -> None:
        native = self.source.split("  native_qemu:", 1)[1].split(
            "  azure_acceptance:", 1
        )[0]
        self.assertIn("test -r /dev/kvm", native)
        self.assertIn("test -w /dev/kvm", native)
        self.assertIn("VMIZ_UBUNTU2604_IMAGE=", native)
        self.assertIn("test -s \"$VMIZ_UBUNTU2604_ACCEPTANCE_RESULT\"", native)
        self.assertIn("tampered-uki-rejected", native)
        self.assertIn("Provision privileged offline-root containment fixture", native)
        self.assertIn(
            'sudo -E "$(command -v zig)" test packages/vmiz/src/offline_root.zig',
            native,
        )
        self.assertIn('sudo rm -rf -- "$fixture"', native)
        self.assertNotIn("/usr/bin/coreutils", native)
        self.assertIn('ldd "$binary"', native)
        self.assertIn("while read -r library", native)


if __name__ == "__main__":
    unittest.main()
