"""Static validation tests for scripts/freebsd15_azure_acceptance.sh."""

import os
import stat
import subprocess
import sys

SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "freebsd15_azure_acceptance.sh",
)


def test_script_exists_and_executable():
    assert os.path.isfile(SCRIPT)
    mode = os.stat(SCRIPT).st_mode
    assert mode & stat.S_IXUSR


def test_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", SCRIPT],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Syntax error: {result.stderr}"


def test_has_strict_mode():
    with open(SCRIPT) as f:
        content = f.read()
    assert "set -Eeuo pipefail" in content


def test_run_and_cleanup_modes():
    with open(SCRIPT) as f:
        content = f.read()
    assert '"$command_name" == cleanup' in content
    assert '"$command_name" != run' in content


def _preflight(candidate_key):
    env = os.environ.copy()
    env.update(
        {
            "STATE_FILE": os.path.join(os.path.dirname(SCRIPT), "unused-state"),
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "CANDIDATE_KEY": candidate_key,
        }
    )
    return subprocess.run(
        [SCRIPT, "invalid-mode"],
        capture_output=True,
        text=True,
        env=env,
    )


def test_candidate_key_accepts_supported_profiles():
    for architecture in ("x86_64", "aarch64"):
        for profile in ("ufs-full", "ufs-core", "zfs-full"):
            result = _preflight(f"{architecture}-{profile}")
            assert result.returncode == 2, (profile, result.stderr)


def test_candidate_key_rejects_unsupported_profiles_fail_closed():
    for key in (
        "x86_64-zfs-core",
        "aarch64-zfs-core",
        "x86_64-ufs-minimal",
        "riscv64-ufs-core",
    ):
        assert _preflight(key).returncode == 1


def test_candidate_manifest_uses_canonical_validation():
    with open(SCRIPT) as f:
        content = f.read()
    assert "release.validate_candidate(" in content
    assert "candidate asset path does not match manifest" in content
    assert "candidate asset name mismatch" in content
    assert 'doc.get("architecture") != architecture' in content
    assert 'doc.get("filesystem") != filesystem' in content
    assert 'doc.get("flavor") != flavor' in content
    assert '("ufs", "core")' in content
    assert '("zfs", "full")' in content
    assert "candidate compressed size is missing or invalid" in content
    assert "candidate allocated size is missing or invalid" in content
    assert "candidate source size is missing or invalid" in content
    assert "candidate package manifest is missing" in content
    assert "candidate package installed size is missing or invalid" in content
    assert 'Path(f"{requested_asset}.packages.txt").resolve(strict=True)' in content
    assert "release.parse_package_manifest(package_manifest_path)" in content
    assert "release.verify_package_manifest(flavor, installed_packages)" in content
    assert "candidate package manifest content does not match" in content
    assert "candidate package manifest count does not match" in content
    assert "candidate package manifest installed size does not match" in content
    assert "candidate validation metadata is missing" in content
    assert "candidate validation runner does not match profile" in content
    assert "candidate validation workflow identity mismatch" in content


def test_candidate_is_revalidated_before_result_generation():
    with open(SCRIPT) as f:
        content = f.read()
    assert content.count("validate_candidate_binding") >= 3
    assert "readarray -t result_candidate" in content
    assert 'test "${result_candidate[0]}" = "$qcow_sha256"' in content
    assert 'test "${result_candidate[1]}" = "$qcow_bytes"' in content
    assert 'test "${result_candidate[2]}" = "$qcow_allocated_size"' in content
    assert 'test "${result_candidate[3]}" = "$virtual_size"' in content
    assert 'test "${result_candidate[4]}" = "$candidate_architecture"' in content


def test_ownership_tags_use_freebsd15():
    with open(SCRIPT) as f:
        content = f.read()
    assert "zvmi-owner=freebsd15-release" in content


def test_resource_group_prefix():
    with open(SCRIPT) as f:
        content = f.read()
    assert 'zvmi-fb15-${GITHUB_RUN_ID}' in content


def test_contracts_set():
    with open(SCRIPT) as f:
        content = f.read()
    assert (
        'shared_contracts_before_storage="matching-architecture-gen2,'
        'key-only-ssh,agent-ready,hn0-dhcp,serial-console"'
    ) in content
    assert (
        'shared_contracts_after_storage="root-growth,gpt-healthy,'
        'reboot-reconnect,instance-identity"'
    ) in content
    assert 'filesystem_contracts="zfs-root,zpool-healthy"' in content
    assert (
        'filesystem_contracts="ufs-root,ufs-root-partition-growth,'
        'ufs-root-filesystem-growth,no-os-disk-swap"'
    ) in content
    assert (
        'contracts="$shared_contracts_before_storage,$filesystem_contracts,'
        '$shared_contracts_after_storage"'
    ) in content


def test_zfs_contract_result_remains_backward_compatible():
    expected = (
        "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp,"
        "serial-console,zfs-root,zpool-healthy,root-growth,gpt-healthy,"
        "reboot-reconnect,instance-identity"
    )
    before = (
        "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp,"
        "serial-console"
    )
    storage = "zfs-root,zpool-healthy"
    after = "root-growth,gpt-healthy,reboot-reconnect,instance-identity"
    assert ",".join((before, storage, after)) == expected


def test_never_retains_vhd():
    with open(SCRIPT) as f:
        content = f.read()
    assert 'rm -f -- "$vhd"' in content


def test_gen2_disk():
    with open(SCRIPT) as f:
        content = f.read()
    assert "--hyper-v-generation V2" in content


def test_expanded_disk():
    with open(SCRIPT) as f:
        content = f.read()
    assert "az disk update" in content
    assert "--size-gb" in content


def test_reboot_reconnect_contract():
    with open(SCRIPT) as f:
        content = f.read()
    assert "reboot_and_reconnect" in content
    assert "pre_reboot_hostkey" in content
    assert "post_reboot_hostkey" in content


def test_zfs_root_validation():
    with open(SCRIPT) as f:
        content = f.read()
    assert 'zpool status -x "$root_pool"' in content
    assert 'zpool get -H -o value autoexpand "$root_pool"' in content
    assert "pre_reboot_storage_identity" in content
    assert "post_reboot_storage_identity" in content


def test_ufs_root_and_growth_validation_has_no_zfs_assumptions():
    with open(SCRIPT) as f:
        content = f.read()
    start = content.index("    # ufs-root and UFS growth:")
    end = content.index("    ;;", start)
    ufs_checks = content[start:end]
    assert "mount -p" not in ufs_checks  # Root type is checked before dispatch.
    assert "diskinfo" in ufs_checks
    assert "df -k /" in ufs_checks
    assert "root_partition_size" in ufs_checks
    assert "root_filesystem_kib" in ufs_checks
    assert "zpool" not in ufs_checks
    assert "zfs " not in ufs_checks


def test_gpt_health_and_no_os_disk_swap():
    with open(SCRIPT) as f:
        content = f.read()
    assert '! gpart show "$disk" | grep -q CORRUPT' in content
    assert 'gpart status -s "$disk"' in content
    assert "require_resource_disk_provider" in content
    assert '"$resource_disk" = "$disk"' in content
    assert "swap provider is not positively identified as resource-disk-backed" in content


def test_md_backed_root_swap_file_is_rejected():
    with open(SCRIPT) as f:
        content = f.read()
    start = content.index("    md[0-9]*)")
    end = content.index("      ;;", start)
    md_checks = content[start:end]
    assert 'mdconfig -lv -u "$md_unit"' in md_checks
    assert '$2 == "vnode" { print $4; exit }' in md_checks
    assert 'md_backing_mount=$(df -k "$md_backing"' in md_checks
    assert 'md_backing_device=$(df -k "$md_backing"' in md_checks
    assert '[ "$md_backing_mount" = / ]' in md_checks
    assert "swap vnode is backed by the OS/root filesystem" in md_checks
    assert 'require_resource_disk_provider "$md_backing_provider"' in md_checks


def test_mdconfig_verbose_parser_uses_only_backing_file_field():
    fixtures = (
        (
            "md0\tvnode\t 2.0G\t/swapfile\troot-swap\tasync,cache,compress\n",
            "/swapfile",
        ),
        (
            "md7\tvnode\t 1.0G\t/mnt/resource/swap file\tazure swap\t"
            "cache,readonly,verify\n",
            "/mnt/resource/swap file",
        ),
    )
    for row, expected in fixtures:
        result = subprocess.run(
            ["awk", "-F", "\t", '$2 == "vnode" { print $4; exit }'],
            input=row,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.rstrip("\n") == expected


def test_resource_disk_provider_parser_supports_gpt_and_mbr():
    fixtures = (
        ("da1p1", "da1"),
        ("nda2p3", "nda2"),
        ("da1s1", "da1"),
        ("ada2s4", "ada2"),
    )
    for provider, expected_disk in fixtures:
        result = subprocess.run(
            ["sed", "-E", "s/(p|s)[0-9]+$//"],
            input=f"{provider}\n",
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == expected_disk

    with open(SCRIPT) as f:
        content = f.read()
    assert "sed -E 's/(p|s)[0-9]+$//'" in content
    assert "*p[0-9]*|*s[0-9]*)" in content


def test_clean_shutdown_is_observed():
    with open(SCRIPT) as f:
        content = f.read()
    assert "wait_for_poweroff" in content
    assert "PowerState/stopped|PowerState/deallocated" in content


def test_all_results_use_canonical_schema3_writer():
    with open(SCRIPT) as f:
        content = f.read()
    assert content.count("freebsd15_release.py azure-result") == 1
    assert "UFS result writer" not in content
    assert "qcow_allocated_size" in content
    assert "qcow_bytes" in content


def test_no_default_freebsd_account():
    with open(SCRIPT) as f:
        content = f.read()
    assert "! id freebsd" in content


def test_locked_root():
    with open(SCRIPT) as f:
        content = f.read()
    assert "root account is not locked" in content


# --- Workflow integration tests ---

WORKFLOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".github",
    "workflows",
    "freebsd15-release.yml",
)


def _workflow_content():
    with open(WORKFLOW) as f:
        return f.read()


def test_workflow_azure_acceptance_job_exists():
    content = _workflow_content()
    assert "azure_acceptance:" in content


def test_workflow_azure_acceptance_for_zfs_and_core_only():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : idx + 600]
    assert "inputs.release_set == 'zfs'" in section
    assert "inputs.release_set == 'core'" in section


def test_workflow_azure_acceptance_uses_release_set_matrix():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "fromJSON(needs.prepare.outputs.azure_matrix)" in section
    assert "CANDIDATE_KEY: ${{ matrix.key }}" in section
    assert "AZURE_LOCATION: ${{ vars[matrix.location_variable] }}" in section
    assert "AZURE_VM_SIZE: ${{ vars[matrix.size_variable] }}" in section


def test_workflow_publish_depends_on_azure_acceptance():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 400]
    assert "azure_acceptance" in section


def test_workflow_publish_requires_azure_success_for_gated_sets():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 600]
    assert "needs.azure_acceptance.result == 'success'" in section


def test_workflow_publish_allows_skipped_azure_for_non_zfs():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 600]
    assert "inputs.release_set == 'ufs'" in section


def test_workflow_azure_acceptance_uses_oidc():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "id-token: write" in section
    assert "azure/login@" in section
    assert "environment: freebsd15-release" in section
    assert "secrets.AZURE_SUBSCRIPTION_ID" in section


def test_workflow_azure_acceptance_uses_harness():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "scripts/freebsd15_azure_acceptance.sh run" in section
    assert "scripts/freebsd15_azure_acceptance.sh cleanup" in section


def test_workflow_publish_downloads_azure_results_for_zfs_and_core():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx:]
    assert "freebsd15-azure-*" in section
    assert "AZURE_RESULTS_DIR" in section
    assert "inputs.release_set == 'zfs' || inputs.release_set == 'core'" in section


def test_workflow_publish_fail_closed_check():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx:]
    assert 'test "$AZURE_RESULT" = success' in section
    assert 'test "$count" -eq 2' in section


def test_workflow_artifact_naming_consistent():
    import re

    content = _workflow_content()
    artifact_refs = [
        line.strip()
        for line in content.splitlines()
        if re.match(r"\s+(name|pattern): freebsd15-(candidate|azure)-", line)
    ]
    # build uploads candidate (1), azure_acceptance downloads candidate (2) +
    # uploads azure result (2) + failure (2), publish downloads candidates (1) +
    # azure results (1) = various references
    for ref in artifact_refs:
        assert "${{ needs.prepare.outputs.source_commit }}" in ref or \
            "source_commit" in ref


def test_workflow_persists_exact_qemu_info_for_candidate_metadata():
    content = _workflow_content()
    assert (
        'qemu-img info --output=json "$asset" > "$image_info"'
        in content
    )
    assert '--qemu-info "$CANDIDATE_DIR/qemu-img-info.json"' in content
    assert 'jq -r \'.\"actual-size\"\' "$CANDIDATE_DIR/qemu-img-info.json"' in content


def test_core_workflow_builds_and_separates_full_ufs_baselines():
    content = _workflow_content()
    assert "BASELINE_CANDIDATES_DIR" in content
    assert "freebsd15-candidate-*-ufs-core-" in content
    assert "freebsd15-candidate-*-ufs-full-" in content
    assert "Download exact core publication candidates" in content
    assert "Download exact full UFS baseline candidates" in content
    assert "merge-multiple: false" in content


def test_core_release_date_is_explicit_and_not_stale():
    content = _workflow_content()
    assert "core_release_date:" in content
    assert "Explicit reviewed YYYYMMDD" in content
    assert "CORE_RELEASE_DATE" in content
    assert "--release-date" in content
    assert "20260730" not in content


def test_ufs_full_does_not_require_azure_results():
    content = _workflow_content()
    publish = content[content.index("\n  publish:") :]
    assert "inputs.release_set == 'ufs' ||" in publish
    assert "inputs.release_set != 'ufs' && '.release/freebsd15/azure-results'" in publish
