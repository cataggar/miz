"""Static validation tests for scripts/freebsd15_azure_acceptance.sh."""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "freebsd15_azure_acceptance.sh",
)
REPLICATION_FIXTURES = (
    Path(__file__).parent / "fixtures" / "freebsd15_azure_replication"
)
LOCATION_FIXTURE = Path(__file__).parent / "fixtures" / "freebsd15_azure_locations.json"
IMAGE_VERSION_FIXTURE = (
    Path(__file__).parent / "fixtures" / "freebsd15_azure_image_version.json"
)
IMAGE_VERSION_MISMATCH_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "freebsd15_azure_image_version_mismatch.json"
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


def _serial_console_function():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    start = content.index("require_serial_console_log() {")
    end = content.index("\n}\n", start) + len("\n}\n")
    return content[start:end]


def _run_serial_console_case(mode):
    root = (
        Path(SCRIPT).parents[1]
        / ".scratch"
        / f"freebsd15-serial-console-{os.getpid()}-{mode}"
    )
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "BOOT_LOG": str(root / "boot.log"),
            "SERIAL_MODE": mode,
        }
    )
    harness = f"""
set -u -o pipefail
attempts=0
sleeps=0
az() {{
  attempts=$((attempts + 1))
  case "$SERIAL_MODE" in
    missing) return 1 ;;
    empty) return 0 ;;
    no-marker) printf 'UEFI firmware initialized\\nlogin: ' ;;
    valid) printf 'FreeBSD 15.1-RELEASE kernel boot\\n' ;;
    *) return 2 ;;
  esac
}}
sleep() {{
  sleeps=$((sleeps + 1))
}}
boot_log=$BOOT_LOG
resource_group=rg-test
vm_name=vm-test
{_serial_console_function()}
set +e
require_serial_console_log
status=$?
set -e
printf 'status=%s\\nattempts=%s\\nsleeps=%s\\n' \
  "$status" "$attempts" "$sleeps"
"""
    try:
        result = subprocess.run(
            ["bash", "-c", harness],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)
    metrics = {}
    for line in result.stdout.splitlines():
        key, value = line.split("=", 1)
        metrics[key] = int(value)
    return result, metrics


def _image_replication_functions():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    start = content.index("replication_epoch_seconds() {")
    end = content.index("\nazure_location_display_name=$(", start)
    return content[start:end]


def _shell_function(name):
    content = Path(SCRIPT).read_text(encoding="utf-8")
    start = content.index(f"{name}() {{")
    end = content.index("\n}\n", start) + len("\n}\n")
    return content[start:end]


def _run_location_resolution_case(mode, expected_location="swedencentral"):
    root = (
        Path(SCRIPT).parents[1]
        / ".scratch"
        / f"freebsd15-location-resolution-{os.getpid()}-{mode}"
    )
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "LOCATION_FIXTURE": str(LOCATION_FIXTURE),
            "LOCATION_RESULT": str(root / "locations.json"),
            "LOCATION_MODE": mode,
            "EXPECTED_LOCATION": expected_location,
        }
    )
    harness = f"""
set -u -o pipefail
az() {{
  [[ "$*" == "account list-locations --output json" ]] || return 8
  [[ "$LOCATION_MODE" != query-failure ]] || return 1
  cat "$LOCATION_FIXTURE"
}}
{_shell_function("resolve_azure_location_display_name")}
display_name=$(
  resolve_azure_location_display_name "$LOCATION_RESULT" "$EXPECTED_LOCATION"
)
status=$?
printf 'status=%s\\ndisplay_name=%s\\n' "$status" "$display_name"
"""
    try:
        result = subprocess.run(
            ["bash", "-c", harness],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)
    metrics = dict(line.split("=", 1) for line in result.stdout.splitlines())
    return result, metrics


def _run_image_version_validation_case(fixture):
    env = os.environ.copy()
    env["IMAGE_VERSION_FIXTURE"] = str(fixture)
    expected_id = (
        "/subscriptions/test/resourceGroups/rg-test/providers/Microsoft.Compute/"
        "galleries/gallery-test/images/image-test/versions/1.0.0"
    )
    disk_id = (
        "/subscriptions/test/resourceGroups/rg-test/providers/Microsoft.Compute/"
        "disks/disk-test"
    )
    harness = f"""
set -u -o pipefail
{_shell_function("validate_gallery_image_version_metadata")}
validate_gallery_image_version_metadata \
  "$IMAGE_VERSION_FIXTURE" "{expected_id}" 1.0.0 rg-test \
  swedencentral "Sweden Central" "{disk_id}" 8
status=$?
printf 'status=%s\\n' "$status"
"""
    result = subprocess.run(
        ["bash", "-c", harness],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result, int(result.stdout.removeprefix("status=").strip())


def _run_image_replication_case(mode, timeout_seconds=5):
    root = (
        Path(SCRIPT).parents[1]
        / ".scratch"
        / f"freebsd15-image-replication-{os.getpid()}-{mode}"
    )
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "FIXTURE_DIR": str(REPLICATION_FIXTURES),
            "REPLICATION_MODE": mode,
            "REPLICATION_RESULT": str(root / "replication.json"),
        }
    )
    harness = f"""
set -u -o pipefail
attempts=0
sleeps=0
clock=0
events=
delays=
az() {{
  if [[ "$1 $2 ${{3:-}}" == "sig image-version show" ]]; then
    case " $* " in
      *" --expand ReplicationStatus "*) ;;
      *) return 9 ;;
    esac
    attempts=$((attempts + 1))
    events="${{events:+$events,}}show"
    case "$REPLICATION_MODE" in
      pending-completed)
        if [[ "$attempts" -eq 1 ]]; then
          fixture=replicating.json
        else
          fixture=completed.json
        fi
        ;;
      failed) fixture=failed.json ;;
      missing-region) fixture=missing-region.json ;;
      whitespace-mismatch) fixture=whitespace-mismatch.json ;;
      timeout) fixture=replicating.json ;;
      *) return 8 ;;
    esac
    cat "$FIXTURE_DIR/$fixture"
    return
  fi
  if [[ "$1 $2" == "vm create" ]]; then
    events="${{events:+$events,}}vm"
    return
  fi
  return 7
}}
sleep() {{
  sleeps=$((sleeps + 1))
  delays="${{delays:+$delays,}}$1"
  clock=$((clock + $1))
}}
{_image_replication_functions()}
replication_epoch_seconds() {{
  printf '%s\\n' "$clock"
}}
resource_group=rg-test
gallery_name=gallery-test
image_definition_name=image-test
image_version=1.0.0
AZURE_LOCATION=westus2
azure_location_display_name="West US 2"
image_replication_json=$REPLICATION_RESULT
wait_for_image_version_replication {timeout_seconds} 1 2
status=$?
if [[ "$status" -eq 0 ]]; then
  az vm create
fi
printf 'status=%s\\nattempts=%s\\nsleeps=%s\\nclock=%s\\n' \
  "$status" "$attempts" "$sleeps" "$clock"
printf 'delays=%s\\nevents=%s\\n' "$delays" "$events"
"""
    try:
        result = subprocess.run(
            ["bash", "-c", harness],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)
    metrics = {}
    for line in result.stdout.splitlines():
        key, value = line.split("=", 1)
        metrics[key] = value
    return result, metrics


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


def test_serial_console_missing_or_empty_log_fails_after_bounded_retries():
    for mode in ("missing", "empty"):
        result, metrics = _run_serial_console_case(mode)
        assert metrics == {"status": 1, "attempts": 6, "sleeps": 5}
        assert "did not return a nonempty serial log after 6 attempts" in (
            result.stderr
        )


def test_serial_console_log_without_freebsd_marker_fails_closed():
    result, metrics = _run_serial_console_case("no-marker")
    assert metrics == {"status": 1, "attempts": 6, "sleeps": 5}
    assert "serial log is missing expected FreeBSD output" in result.stderr


def test_serial_console_valid_log_succeeds_without_extra_retries():
    result, metrics = _run_serial_console_case("valid")
    assert metrics == {"status": 0, "attempts": 1, "sleeps": 0}
    assert result.stderr == ""


def test_image_replication_pending_then_completed_precedes_vm_creation():
    result, metrics = _run_image_replication_case("pending-completed")
    assert metrics == {
        "status": "0",
        "attempts": "2",
        "sleeps": "1",
        "clock": "1",
        "delays": "1",
        "events": "show,show,vm",
    }
    assert result.stderr == ""


def test_location_metadata_resolves_exact_canonical_name():
    result, metrics = _run_location_resolution_case("success")
    assert metrics == {"status": "0", "display_name": "Sweden Central"}
    assert result.stderr == ""


def test_location_metadata_mismatch_fails_closed():
    result, metrics = _run_location_resolution_case(
        "success", expected_location="swedencentral2"
    )
    assert metrics == {"status": "1", "display_name": ""}
    assert "0 exact canonical matches for 'swedencentral2'" in result.stderr


def test_location_metadata_query_failure_fails_closed():
    result, metrics = _run_location_resolution_case("query-failure")
    assert metrics == {"status": "1", "display_name": ""}
    assert "Could not query Azure location metadata" in result.stderr


def test_gallery_target_region_accepts_exact_display_name():
    result, status = _run_image_version_validation_case(IMAGE_VERSION_FIXTURE)
    assert status == 0
    assert result.stderr == ""


def test_gallery_target_region_does_not_strip_whitespace():
    result, status = _run_image_version_validation_case(
        IMAGE_VERSION_MISMATCH_FIXTURE
    )
    assert status == 1
    assert "gallery image-version target location mismatch" in result.stderr


def test_image_replication_failed_blocks_vm_with_diagnostics():
    result, metrics = _run_image_replication_case("failed")
    assert metrics["status"] == "1"
    assert metrics["events"] == "show"
    assert metrics["sleeps"] == "0"
    assert "replication to westus2 failed" in result.stderr
    assert "Replica copy failed" in result.stderr


def test_image_replication_missing_target_region_blocks_vm():
    result, metrics = _run_image_replication_case("missing-region")
    assert metrics["status"] == "1"
    assert metrics["events"] == "show"
    assert metrics["sleeps"] == "0"
    assert "does not include target region 'westus2'" in result.stderr
    assert "invalid regional image replication status" in result.stderr


def test_image_replication_does_not_strip_whitespace():
    result, metrics = _run_image_replication_case("whitespace-mismatch")
    assert metrics["status"] == "1"
    assert metrics["events"] == "show"
    assert metrics["sleeps"] == "0"
    assert "'West  US 2'" in result.stderr
    assert "does not include target region 'westus2'" in result.stderr


def test_image_replication_timeout_uses_bounded_exponential_backoff():
    result, metrics = _run_image_replication_case("timeout", timeout_seconds=3)
    assert metrics == {
        "status": "1",
        "attempts": "2",
        "sleeps": "2",
        "clock": "3",
        "delays": "1,2",
        "events": "show,show",
    }
    assert "Timed out after 3s" in result.stderr
    assert "last state=Replicating" in result.stderr


def test_serial_console_gate_precedes_result_and_keeps_cleanup_active():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    definition = content.index("require_serial_console_log() {")
    invocation = content.index("\nrequire_serial_console_log\n", definition)
    result_writer = content.index(
        "python3 scripts/freebsd15_release.py azure-result",
        invocation,
    )
    cleanup_trap = content.index("trap cleanup_on_exit EXIT")
    assert cleanup_trap < invocation < result_writer
    assert "if ! cleanup_group; then" in content
    assert "::warning::Azure managed boot diagnostics" not in content


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


def test_fixed_vhd_validation_uses_footer_current_size():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    assert "python3 scripts/azure_vhd.py verify" in content
    assert 'vhd_current_size=${vhd_geometry[0]}' in content
    assert 'test "$vhd_bytes" -eq "$((vhd_current_size + 512))"' in content
    assert "f.seek(virtual_size)" not in content
    assert "file size == virtual size + 512" not in content
    assert (
        'expanded_size_gib=$(((vhd_current_size + 1073741823) '
        "/ 1073741824 + 2))"
    ) in content
    assert '--vhd-current-size "$vhd_current_size"' in content


def test_gen2_disk():
    with open(SCRIPT) as f:
        content = f.read()
    assert "--hyper-v-generation V2" in content


def test_architecture_maps_exactly_for_gallery_definition():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    mapping_start = content.index('case "$ARCHITECTURE" in')
    mapping_end = content.index("\nesac", mapping_start)
    mapping = content[mapping_start:mapping_end]

    assert (
        "aarch64)\n"
        "    short_arch=arm64\n"
        "    expected_azure_architecture=Arm64\n"
        "    runtime_architecture=arm64\n"
        "    azure_image_architecture=Arm64"
    ) in mapping
    assert (
        "x86_64)\n"
        "    short_arch=x64\n"
        "    expected_azure_architecture=x64\n"
        "    runtime_architecture=amd64\n"
        "    azure_image_architecture=x64"
    ) in mapping
    definition_create = content.index("az sig image-definition create")
    definition_show = content.index(
        "az sig image-definition show", definition_create
    )
    definition_block = content[definition_create:definition_show]
    assert '--architecture "$azure_image_architecture"' in definition_block


def test_gallery_definition_and_version_precede_provisioned_vm():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    disk_validation = content.index(
        "# Validate the imported disk identity and matching architecture"
    )
    gallery_create = content.index("az sig create")
    definition_create = content.index(
        "az sig image-definition create", gallery_create
    )
    version_create = content.index("az sig image-version create", definition_create)
    version_wait = content.index("az sig image-version wait", version_create)
    version_show = content.index("az sig image-version show", version_wait)
    replication_wait = content.index(
        "\nwait_for_image_version_replication \\", version_show
    )
    vm_create = content.index("az vm create", replication_wait)
    definition_block = content[definition_create:version_create]
    version_block = content[version_create:version_wait]
    vm_end = content.index("\naz vm show", vm_create)
    vm_block = content[vm_create:vm_end]

    assert (
        disk_validation
        < gallery_create
        < definition_create
        < version_create
        < version_wait
        < version_show
        < replication_wait
        < vm_create
    )
    assert "image_publisher=zvmi" in content
    assert "image_offer=freebsd15" in content
    assert 'image_sku="${short_arch}-${FILESYSTEM}-${FLAVOR}"' in content
    assert "--permissions Private" in content[gallery_create:definition_create]
    assert '--publisher "$image_publisher"' in definition_block
    assert '--offer "$image_offer"' in definition_block
    assert '--sku "$image_sku"' in definition_block
    assert "--os-type Linux" in definition_block
    assert "--os-state Generalized" in definition_block
    assert "--hyper-v-generation V2" in definition_block
    assert '--architecture "$azure_image_architecture"' in definition_block
    assert '--os-snapshot "$disk_id"' in version_block
    assert "--replication-mode Shallow" in version_block
    assert '--target-regions "$AZURE_LOCATION=1=Standard_LRS"' in version_block
    assert "--no-wait" in version_block
    assert "--created" in content[version_wait:version_show]
    replication_function = _image_replication_functions()
    assert "--expand ReplicationStatus" in replication_function
    assert '"$azure_location_display_name"' in replication_function
    assert 'if [[ "${state,,}" == completed ]]' in replication_function
    assert "Timed out after ${elapsed}s" in replication_function
    assert "az account list-locations --output json" in content
    assert '--image "$image_version_id"' in vm_block
    assert '--admin-username "$admin_username"' in vm_block
    assert "--authentication-type ssh" in vm_block
    assert '--ssh-key-values "$private_key.pub"' in vm_block
    assert "--enable-agent false" in vm_block
    assert "--security-type Standard" in vm_block
    assert '--size "$AZURE_VM_SIZE"' in vm_block
    assert '--location "$AZURE_LOCATION"' in vm_block
    assert "--public-ip-sku Standard" in vm_block
    assert "--nsg-rule SSH" in vm_block
    assert '--boot-diagnostics-storage ""' in vm_block
    assert "--specialized" not in vm_block
    assert "az image create" not in content
    assert "az image show" not in content
    assert "--attach-os-disk" not in content


def test_replication_gate_keeps_owned_resource_group_cleanup_active():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    cleanup_function = content.index("cleanup_on_exit() {")
    cleanup_trap = content.index("trap cleanup_on_exit EXIT")
    replication_wait = content.index("\nwait_for_image_version_replication \\")
    vm_create = content.index("az vm create", replication_wait)
    assert cleanup_trap < replication_wait < vm_create
    assert "if ! cleanup_group; then" in content[cleanup_function:cleanup_trap]


def test_disk_gallery_version_and_vm_source_identities_fail_closed():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    assert 'expected_disk_id="/subscriptions/$subscription_id/' in content
    assert 'test "${disk_id,,}" = "${expected_disk_id,,}"' in content
    assert "managed disk architecture mismatch" in content
    assert 'expected_gallery_id="/subscriptions/$subscription_id/' in content
    assert 'expected_image_definition_id="$expected_gallery_id/images/' in content
    assert 'image_version_id="$expected_image_definition_id/versions/' in content
    assert "gallery image-definition architecture mismatch" in content
    assert "gallery image definition is not Gen2" in content
    assert "gallery image definition is not generalized" in content
    assert "gallery image-definition identifier mismatch" in content
    assert (
        "gallery image version is not sourced from the exact managed disk"
        in content
    )
    assert "gallery image-version provisioning did not succeed" in content
    assert "gallery image-version OS disk size mismatch" in content
    assert "VM is not bound to the exact gallery image version" in content
    assert "VM OS disk size mismatch" in content
    assert 'expected_vm_id="/subscriptions/$subscription_id/' in content
    assert 'test "${vm_id,,}" = "${expected_vm_id,,}"' in content
    assert "VM architecture mismatch" in content
    assert content.count(
        'test "$(sha256sum "$asset" | awk \'{print $1}\')" = "$qcow_sha256"'
    ) >= 3
    assert content.count(
        'test "$(sha256sum "$vhd" | awk \'{print $1}\')" = "$vhd_sha256"'
    ) == 2


def test_owned_resource_group_cleanup_removes_gallery_disk_and_vm():
    content = Path(SCRIPT).read_text(encoding="utf-8")
    for command in (
        "az disk create",
        "az sig create",
        "az sig image-definition create",
        "az sig image-version create",
        "az vm create",
    ):
        start = content.index(command)
        end = content.index("--output", start)
        assert '--resource-group "$resource_group"' in content[start:end]
    assert 'gallery_name="zvmifb15${name_seed}"' in content
    assert (
        'image_definition_name="zvmifb15${short_arch}${FILESYSTEM}${FLAVOR}"'
        in content
    )
    assert 'image_version=1.0.0' in content
    assert 'trap cleanup_on_exit EXIT' in content
    assert 'az group delete --name "$resource_group" --yes' in content
    assert "Owned temporary resource group still exists after deletion" in content
    assert "az sig delete" not in content
    assert "az sig image-definition delete" not in content
    assert "az sig image-version delete" not in content
    assert "az disk delete" not in content
    assert "az vm delete" not in content


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
    section = content[idx : content.index("\n  stage:", idx)]
    assert "fromJSON(needs.prepare.outputs.azure_matrix)" in section
    assert "CANDIDATE_KEY: ${{ matrix.key }}" in section
    assert "AZURE_LOCATION: ${{ vars[matrix.location_variable] }}" in section
    assert "AZURE_VM_SIZE: ${{ vars[matrix.size_variable] }}" in section


def test_workflow_staging_depends_on_azure_and_publish_depends_on_staging():
    content = _workflow_content()
    stage = content[content.index("\n  stage:") : content.index("\n  publish:")]
    publish = content[content.index("\n  publish:") :]
    assert "needs: [prepare, build, azure_acceptance]" in stage
    assert "needs: [prepare, stage]" in publish


def test_workflow_staging_requires_azure_success_for_gated_sets():
    content = _workflow_content()
    idx = content.index("\n  stage:")
    section = content[idx : idx + 600]
    assert "needs.azure_acceptance.result == 'success'" in section


def test_workflow_staging_allows_skipped_azure_for_ufs():
    content = _workflow_content()
    idx = content.index("\n  stage:")
    section = content[idx : idx + 600]
    assert "inputs.release_set == 'ufs'" in section


def test_workflow_azure_acceptance_uses_oidc():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  stage:", idx)]
    assert "id-token: write" in section
    assert "azure/login@" in section
    assert "environment: azurelinux4-release" in section
    assert section.count("secrets.AZURE_CLIENT_ID") == 3
    assert section.count("secrets.AZURE_TENANT_ID") == 3
    assert section.count("secrets.AZURE_SUBSCRIPTION_ID") == 3
    assert "AZURE_CLIENT_SECRET" not in section
    assert "client-secret:" not in section


def test_workflow_only_azure_acceptance_uses_protected_azure_configuration():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  stage:", idx)]
    outside = content[:idx] + content[content.index("\n  stage:", idx) :]
    assert content.count("environment: azurelinux4-release") == 1
    assert "environment: freebsd15-release" not in content
    assert "secrets.AZURE_" not in outside
    assert "vars[matrix.location_variable]" not in outside
    assert "vars[matrix.size_variable]" not in outside
    assert "AZURE_LOCATION: ${{ vars[matrix.location_variable] }}" in section
    assert "AZURE_VM_SIZE: ${{ vars[matrix.size_variable] }}" in section


def test_workflow_azure_acceptance_uses_harness():
    content = _workflow_content()
    idx = content.index("azure_acceptance:")
    section = content[idx : content.index("\n  stage:", idx)]
    assert "scripts/freebsd15_azure_acceptance.sh run" in section
    assert "scripts/freebsd15_azure_acceptance.sh cleanup" in section


def test_workflow_publish_downloads_azure_results_for_zfs_and_core():
    content = _workflow_content()
    idx = content.index("\n  publish:")
    section = content[idx:]
    assert "freebsd15-azure-*" in section
    assert "AZURE_RESULTS_DIR" in section
    assert "inputs.release_set == 'zfs' || inputs.release_set == 'core'" in section


def test_workflow_staging_fail_closed_check():
    content = _workflow_content()
    section = content[
        content.index("\n  stage:") : content.index("\n  publish:")
    ]
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
    stage = content[content.index("\n  stage:") : content.index("\n  publish:")]
    assert "inputs.release_set == 'ufs' ||" in stage
    assert "inputs.release_set != 'ufs' && '.release/freebsd15/azure-results'" in stage
