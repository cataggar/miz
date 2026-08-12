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


def test_candidate_key_validates_zfs_full_only():
    with open(SCRIPT) as f:
        content = f.read()
    assert "(x86_64|aarch64)-zfs-full" in content


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
    expected = (
        "matching-architecture-gen2,key-only-ssh,agent-ready,"
        "hn0-dhcp,serial-console,zfs-root,zpool-healthy,"
        "root-growth,gpt-healthy,reboot-reconnect,instance-identity"
    )
    assert expected in content


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
    assert "zpool status zroot" in content
    assert "zpool get" in content


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


def test_workflow_azure_acceptance_only_for_zfs():
    content = _workflow_content()
    # The azure_acceptance job condition must include release_set == 'zfs'
    idx = content.index("azure_acceptance:")
    section = content[idx : idx + 600]
    assert "inputs.release_set == 'zfs'" in section


def test_workflow_azure_acceptance_has_both_architectures():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "x86_64-zfs-full" in section
    assert "aarch64-zfs-full" in section
    assert "AZURE_LOCATION_X64" in section
    assert "AZURE_LOCATION_ARM64" in section
    assert "AZURE_VM_SIZE_X64" in section
    assert "AZURE_VM_SIZE_ARM64" in section


def test_workflow_publish_depends_on_azure_acceptance():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 400]
    assert "azure_acceptance" in section


def test_workflow_publish_requires_azure_success_for_zfs():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 600]
    assert "needs.azure_acceptance.result == 'success'" in section


def test_workflow_publish_allows_skipped_azure_for_non_zfs():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx : idx + 600]
    # Non-ZFS should still publish even with azure_acceptance skipped
    assert "inputs.release_set != 'zfs'" in section


def test_workflow_azure_acceptance_uses_oidc():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "id-token: write" in section
    assert "azure/login@" in section


def test_workflow_azure_acceptance_uses_harness():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  publish:", idx)]
    assert "scripts/freebsd15_azure_acceptance.sh run" in section
    assert "scripts/freebsd15_azure_acceptance.sh cleanup" in section


def test_workflow_publish_downloads_azure_results_for_zfs():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx:]
    assert "freebsd15-azure-*" in section
    assert "AZURE_RESULTS_DIR" in section


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
