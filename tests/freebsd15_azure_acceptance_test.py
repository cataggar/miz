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
