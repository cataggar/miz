#!/usr/bin/env bash
# FreeBSD 15 Azure acceptance harness — UFS and ZFS variants (aarch64 / x86_64).
# Validates a candidate QCOW2 by deriving a fixed VHD, uploading to Azure,
# booting a Gen2 VM, and exercising shared and filesystem-specific contracts.
set -Eeuo pipefail

command_name=${1:-run}
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} || -z ${CANDIDATE_KEY:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]]
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
[[ "$CANDIDATE_KEY" =~ ^(x86_64|aarch64)-(ufs|zfs)-(full|core)$ ]]

cleanup_group() {
  [[ -s "$STATE_FILE" ]] || return 0
  command -v az >/dev/null || {
    echo "::error::Azure CLI is unavailable during cleanup"
    return 1
  }
  local resource_group metadata_file group_exists expected_resource_group suffix
  resource_group=$(<"$STATE_FILE")
  suffix=${CANDIDATE_KEY//_/-}
  expected_resource_group="vmiz-fb15-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
  [[ "$resource_group" == "$expected_resource_group" ]] || {
    echo "::error::Refusing cleanup of unexpected resource-group name"
    return 1
  }
  if ! group_exists=$(az group exists --name "$resource_group" --output tsv); then
    echo "::error::Could not determine whether the temporary resource group exists"
    return 1
  fi
  case "$group_exists" in
    false) return 0 ;;
    true) ;;
    *)
      echo "::error::Azure returned an invalid resource-group existence result"
      return 1
      ;;
  esac
  metadata_file="${STATE_FILE}.group.json"
  if ! az group show --name "$resource_group" --output json >"$metadata_file"; then
    echo "::error::Could not inspect temporary resource-group ownership"
    return 1
  fi
  if ! python3 - "$metadata_file" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$CANDIDATE_KEY" <<'PY'
import json
import sys

tags = json.load(open(sys.argv[1], encoding="utf-8")).get("tags") or {}
expected = {
    "vmiz-owner": "freebsd15-release",
    "vmiz-run-id": sys.argv[2],
    "vmiz-run-attempt": sys.argv[3],
    "vmiz-candidate": sys.argv[4],
}
if tags != expected:
    raise SystemExit(f"refusing to delete resource group with non-exact ownership tags: {tags!r}")
PY
  then
    return 1
  fi
  if ! az group delete --name "$resource_group" --yes; then
    echo "::error::Failed to delete owned temporary resource group"
    return 1
  fi
  if ! group_exists=$(az group exists --name "$resource_group" --output tsv); then
    echo "::error::Could not verify temporary resource-group deletion"
    return 1
  fi
  case "$group_exists" in
    false) ;;
    true)
      echo "::error::Owned temporary resource group still exists after deletion"
      return 1
      ;;
    *)
      echo "::error::Azure returned an invalid post-cleanup resource-group result"
      return 1
      ;;
  esac
}

if [[ "$command_name" == cleanup ]]; then
  cleanup_group
  exit
fi
if [[ "$command_name" != run ]]; then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi

# --- Run mode: full acceptance ---
if [[ -z ${CANDIDATE_DIR:-} || -z ${SOURCE_COMMIT:-} || -z ${ARCHITECTURE:-} ||
      -z ${FILESYSTEM:-} || -z ${FLAVOR:-} || -z ${ASSET_NAME:-} ||
      -z ${AZURE_LOCATION:-} || -z ${AZURE_VM_SIZE:-} || -z ${RESULT_DIR:-} ||
      -z ${VMIZ:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$ARCHITECTURE" =~ ^(x86_64|aarch64)$ ]]
case "$FILESYSTEM-$FLAVOR" in
  ufs-full|ufs-core|zfs-full|zfs-core) ;;
  *)
    echo "::error::Unsupported FreeBSD Azure acceptance profile: $FILESYSTEM-$FLAVOR"
    exit 1
    ;;
esac
[[ "$CANDIDATE_KEY" == "$ARCHITECTURE-$FILESYSTEM-$FLAVOR" ]]
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ -x "$VMIZ" ]]

report_error() {
  local status=$1 line=$2 command=$3
  trap - ERR
  printf '::error::Azure acceptance failed at line %s: %s\n' "$line" "$command" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

for tool in az azcopy curl date python3 qemu-img sha256sum ssh ssh-keygen; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required Azure acceptance tool $tool is unavailable"
    exit 1
  }
done

grant_disk_write_access() {
  local disk_id=$1
  local duration_seconds=$2
  local attempt auth_header headers location request_dir response_body retry_after sas status token
  request_dir=$(mktemp -d "$RESULT_DIR/disk-access.XXXXXX")
  auth_header="$request_dir/auth-header"
  headers="$request_dir/headers"
  response_body="$request_dir/body"
  if ! token=$(az account get-access-token \
      --resource https://management.azure.com/ \
      --query accessToken \
      --output tsv)
  then
    echo "::error::Could not acquire an Azure management token" >&2
    rm -rf "$request_dir"
    return 1
  fi
  if [[ -z "$token" ]]; then
    echo "::error::Azure returned an empty management token" >&2
    rm -rf "$request_dir"
    return 1
  fi
  (umask 077; printf 'Authorization: Bearer %s' "$token" >"$auth_header")
  token=

  if ! status=$(curl \
      --silent \
      --show-error \
      --connect-timeout 30 \
      --max-time 60 \
      --retry 3 \
      --retry-max-time 120 \
      --dump-header "$headers" \
      --output "$response_body" \
      --write-out '%{http_code}' \
      --request POST \
      --header "@$auth_header" \
      --header 'Content-Type: application/json' \
      --data "{\"access\":\"Write\",\"durationInSeconds\":$duration_seconds}" \
      "https://management.azure.com${disk_id}/beginGetAccess?api-version=2025-01-02")
  then
    echo "::error::Azure disk access request failed" >&2
    rm -rf "$request_dir"
    return 1
  fi
  if [[ "$status" == 202 ]]; then
    location=$(
      awk -F: '
        tolower($1) == "location" {
          sub(/^[^:]*:[[:space:]]*/, "")
          sub(/\r$/, "")
          print
          exit
        }
      ' "$headers"
    )
    if [[ "$location" != https://* ]]; then
      echo "::error::Azure disk access response omitted the polling location" >&2
      rm -rf "$request_dir"
      return 1
    fi
    for ((attempt = 1; attempt <= 60; attempt++)); do
      retry_after=$(
        awk -F: '
          tolower($1) == "retry-after" {
            sub(/^[^:]*:[[:space:]]*/, "")
            sub(/\r$/, "")
            print
            exit
          }
        ' "$headers"
      )
      if [[ ! "$retry_after" =~ ^[0-9]+$ || "$retry_after" -lt 1 ]]; then
        retry_after=2
      elif [[ "$retry_after" -gt 30 ]]; then
        retry_after=30
      fi
      sleep "$retry_after"
      if ! status=$(curl \
          --silent \
          --show-error \
          --connect-timeout 30 \
          --max-time 60 \
          --retry 3 \
          --retry-max-time 120 \
          --dump-header "$headers" \
          --output "$response_body" \
          --write-out '%{http_code}' \
          --header "@$auth_header" \
          "$location")
      then
        echo "::error::Azure disk access polling request failed" >&2
        rm -rf "$request_dir"
        return 1
      fi
      [[ "$status" == 202 ]] || break
    done
  fi
  if [[ "$status" != 200 ]]; then
    echo "::error::Azure disk access polling ended with HTTP $status" >&2
    rm -rf "$request_dir"
    return 1
  fi
  if ! sas=$(
      python3 - "$response_body" <<'PY'
import json
import sys

response = json.load(open(sys.argv[1], encoding="utf-8"))
print(response.get("accessSAS") or response.get("accessSas") or "")
PY
    )
  then
    echo "::error::Azure disk access response was not valid JSON" >&2
    rm -rf "$request_dir"
    return 1
  fi
  rm -rf "$request_dir"
  if [[ "$sas" != https://* ]]; then
    echo "::error::Azure disk access response omitted the SAS URL" >&2
    return 1
  fi
  printf '%s\n' "$sas"
}

mkdir -p "$RESULT_DIR"
manifest="$CANDIDATE_DIR/candidate.json"
asset="$CANDIDATE_DIR/$ASSET_NAME"

validate_candidate_binding() {
  python3 - "$manifest" "$asset" "$CANDIDATE_KEY" "$SOURCE_COMMIT" \
    "$ARCHITECTURE" "$FILESYSTEM" "$FLAVOR" "$ASSET_NAME" \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" scripts/freebsd15_release.py <<'PY'
import importlib.util
import sys
from pathlib import Path

(
    manifest_path,
    asset_path,
    key,
    source_commit,
    architecture,
    filesystem,
    flavor,
    asset_name,
    run_id,
    run_attempt,
    helper_path,
) = sys.argv[1:]

helper = Path(helper_path).resolve(strict=True)
spec = importlib.util.spec_from_file_location("freebsd15_release", helper)
if spec is None or spec.loader is None:
    raise SystemExit("could not load canonical candidate validator")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

doc, canonical_asset = release.validate_candidate(
    Path(manifest_path).resolve(strict=True),
    source_commit,
)
requested_asset = Path(asset_path).resolve(strict=True)
if requested_asset != canonical_asset.resolve():
    raise SystemExit("candidate asset path does not match manifest")
if requested_asset.name != asset_name or doc.get("asset_name") != asset_name:
    raise SystemExit("candidate asset name mismatch")
if doc.get("variant") != key:
    raise SystemExit(f"candidate variant mismatch: expected {key}")
if doc.get("architecture") != architecture:
    raise SystemExit("candidate architecture mismatch")
if doc.get("filesystem") != filesystem:
    raise SystemExit("candidate filesystem mismatch")
if doc.get("flavor") != flavor:
    raise SystemExit("candidate flavor mismatch")
if (filesystem, flavor) not in {
    ("ufs", "full"),
    ("ufs", "core"),
    ("zfs", "full"),
    ("zfs", "core"),
}:
    raise SystemExit("unsupported candidate filesystem/flavor combination")
if not isinstance(doc.get("compressed_size"), int) or doc["compressed_size"] <= 0:
    raise SystemExit("candidate compressed size is missing or invalid")
if not isinstance(doc.get("allocated_size"), int) or doc["allocated_size"] <= 0:
    raise SystemExit("candidate allocated size is missing or invalid")
if not isinstance(doc.get("virtual_size"), int) or doc["virtual_size"] <= 0:
    raise SystemExit("candidate virtual size is missing or invalid")
source = doc.get("source")
if not isinstance(source, dict):
    raise SystemExit("candidate source metadata is missing")
if not isinstance(source.get("bytes"), int) or source["bytes"] <= 0:
    raise SystemExit("candidate source size is missing or invalid")
packages = doc.get("packages")
if not isinstance(packages, dict):
    raise SystemExit("candidate package manifest is missing")
if not isinstance(packages.get("installed_bytes"), int) or packages["installed_bytes"] <= 0:
    raise SystemExit("candidate package installed size is missing or invalid")
package_manifest_path = Path(f"{requested_asset}.packages.txt").resolve(strict=True)
installed_packages = release.parse_package_manifest(package_manifest_path)
release.verify_package_manifest(filesystem, flavor, installed_packages)
if [package["name"] for package in installed_packages] != packages.get("names"):
    raise SystemExit("candidate package manifest content does not match")
if len(installed_packages) != packages.get("count"):
    raise SystemExit("candidate package manifest count does not match")
if sum(package["installed_bytes"] for package in installed_packages) != packages["installed_bytes"]:
    raise SystemExit("candidate package manifest installed size does not match")
validation = doc.get("validation")
if not isinstance(validation, dict):
    raise SystemExit("candidate validation metadata is missing")
for field in ("qemu_version", "runner", "run_id", "run_attempt"):
    value = validation.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"candidate validation metadata is missing {field}")
if validation["runner"] != release.VARIANTS[key]["runner"]:
    raise SystemExit("candidate validation runner does not match profile")
if validation["run_id"] != run_id or validation["run_attempt"] != run_attempt:
    raise SystemExit("candidate validation workflow identity mismatch")
print(doc["asset_sha256"])
print(doc["compressed_size"])
print(doc["allocated_size"])
print(doc["virtual_size"])
print(doc["architecture"])
PY
}

# Canonically validate every candidate field before creating Azure resources.
readarray -t candidate < <(
  validate_candidate_binding
)
test "${#candidate[@]}" -eq 5
qcow_sha256=${candidate[0]}
qcow_bytes=${candidate[1]}
qcow_allocated_size=${candidate[2]}
virtual_size=${candidate[3]}
candidate_architecture=${candidate[4]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_bytes" =~ ^[0-9]+$ ]]
[[ "$qcow_allocated_size" =~ ^[0-9]+$ ]]
[[ "$virtual_size" =~ ^[0-9]+$ ]]
[[ "$candidate_architecture" == "$ARCHITECTURE" ]]

set_architecture_profile() {
  case "$1" in
    aarch64)
      short_arch=arm64
      expected_azure_architecture=Arm64
      runtime_architecture=aarch64
      azure_image_architecture=Arm64
      ;;
    x86_64)
      short_arch=x64
      expected_azure_architecture=x64
      runtime_architecture=amd64
      azure_image_architecture=x64
      ;;
  esac
}

suffix=${CANDIDATE_KEY//_/-}
resource_group="vmiz-fb15-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
set_architecture_profile "$ARCHITECTURE"
name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}${short_arch}${FILESYSTEM}${FLAVOR}"
disk_name="vmiz-os-${name_seed}"
gallery_name="vmizfb15${name_seed}"
image_definition_name="vmizfb15${short_arch}${FILESYSTEM}${FLAVOR}"
image_version=1.0.0
image_publisher=vmiz
image_offer=freebsd15
image_sku="${short_arch}-${FILESYSTEM}-${FLAVOR}"
vm_name="vmiz-vm-${name_seed}"
admin_username=vmiztest
vhd="$RESULT_DIR/${CANDIDATE_KEY}.vhd"
private_key="$RESULT_DIR/id_ed25519"
boot_log="$RESULT_DIR/boot.log"
boot_log_candidate="$RESULT_DIR/boot.log.candidate"
boot_log_raw="$RESULT_DIR/boot.log.raw"
boot_log_stderr="$RESULT_DIR/boot.log.stderr"
cleanup_boot_log="$RESULT_DIR/boot.log.cleanup"
cleanup_boot_log_raw="$RESULT_DIR/boot.log.cleanup.raw"
cleanup_boot_log_stderr="$RESULT_DIR/boot.log.cleanup.stderr"
sku_json="$RESULT_DIR/sku.json"
disk_json="$RESULT_DIR/disk.json"
gallery_json="$RESULT_DIR/gallery.json"
image_definition_json="$RESULT_DIR/image-definition.json"
image_version_json="$RESULT_DIR/image-version.json"
image_replication_json="$RESULT_DIR/image-version-replication.json"
azure_locations_json="$RESULT_DIR/azure-locations.json"
vm_json="$RESULT_DIR/vm.json"
boot_diagnostics_enable_json="$RESULT_DIR/boot-diagnostics-enable.json"
boot_diagnostics_enable_stderr="$RESULT_DIR/boot-diagnostics-enable.stderr"
vm_show_stderr="$RESULT_DIR/vm-show.stderr"
mkdir -p "$(dirname -- "$STATE_FILE")"
rm -f -- "$STATE_FILE" "${STATE_FILE}.group.json" "$vhd" "$private_key" "$private_key.pub"

normalize_serial_console_response() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

raw_path, output_path = map(Path, sys.argv[1:])
raw = raw_path.read_bytes()
output_path.unlink(missing_ok=True)

try:
    decoded = raw.decode("utf-8")
except UnicodeDecodeError:
    decoded = None

candidate = raw
if decoded is not None:
    try:
        document = json.loads(decoded)
    except json.JSONDecodeError:
        pass
    else:
        if not isinstance(document, str):
            raise SystemExit(12)
        candidate = document.encode("utf-8")

if not candidate.strip():
    raise SystemExit(11)

text = candidate.decode("utf-8", errors="replace")
stripped = text.lstrip()
if stripped.startswith("<"):
    try:
        root = ET.fromstring(stripped)
    except ET.ParseError:
        if stripped.startswith(("<?xml", "<Error", "<error")):
            raise SystemExit(12)
    else:
        if root.tag.rsplit("}", 1)[-1].casefold() == "error":
            code = next(
                (
                    (element.text or "").strip()
                    for element in root
                    if element.tag.rsplit("}", 1)[-1].casefold() == "code"
                ),
                "",
            )
            if code.casefold() == "blobnotfound":
                raise SystemExit(10)
            raise SystemExit(12)

output_path.write_bytes(candidate)
PY
}

collect_failure_boot_log() {
  rm -f -- "$cleanup_boot_log" "$cleanup_boot_log_raw" \
    "$cleanup_boot_log_stderr"
  if ! az vm boot-diagnostics get-boot-log \
    --resource-group "$resource_group" \
    --name "$vm_name" >"$cleanup_boot_log_raw" \
    2>"$cleanup_boot_log_stderr"
  then
    return 0
  fi
  if normalize_serial_console_response \
    "$cleanup_boot_log_raw" "$cleanup_boot_log"
  then
    if [[ -s "$boot_log" ]]; then
      rm -f -- "$cleanup_boot_log"
    else
      mv -- "$cleanup_boot_log" "$boot_log"
    fi
  else
    rm -f -- "$cleanup_boot_log"
  fi
}

serial_console_epoch_seconds() {
  date +%s
}

require_serial_console_log() {
  local timeout_seconds=${1:-${AZURE_SERIAL_LOG_TIMEOUT_SECONDS:-120}}
  local delay_seconds=${2:-${AZURE_SERIAL_LOG_POLL_SECONDS:-5}}
  local attempt=0 deadline elapsed normalization_status now observation
  local saw_real_content=false sleep_seconds started_at

  if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ||
        ! "$delay_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::Invalid Azure serial log timeout configuration" >&2
    return 1
  fi

  rm -f -- "$boot_log" "$boot_log_candidate" "$boot_log_raw" \
    "$boot_log_stderr"
  started_at=$(serial_console_epoch_seconds)
  deadline=$((started_at + timeout_seconds))
  observation="no Azure serial log response"

  while true; do
    now=$(serial_console_epoch_seconds)
    if [[ "$attempt" -gt 0 && "$now" -ge "$deadline" ]]; then
      break
    fi
    attempt=$((attempt + 1))

    if az vm boot-diagnostics get-boot-log \
      --resource-group "$resource_group" \
      --name "$vm_name" >"$boot_log_raw" 2>"$boot_log_stderr"
    then
      normalization_status=0
      normalize_serial_console_response "$boot_log_raw" "$boot_log_candidate" ||
        normalization_status=$?
      case "$normalization_status" in
        0)
          mv -- "$boot_log_candidate" "$boot_log"
          saw_real_content=true
          observation="real serial content without a FreeBSD marker"
          if grep -a -iq 'FreeBSD' "$boot_log"; then
            return
          fi
          ;;
        10)
          observation="Azure boot diagnostics blob is not available yet"
          ;;
        11)
          observation="Azure returned an empty serial log"
          ;;
        12)
          observation="Azure returned a structured error instead of serial content"
          ;;
        *)
          echo "::error::Could not normalize Azure serial log response;" \
            "raw response saved to $boot_log_raw" >&2
          return 1
          ;;
      esac
    else
      observation="Azure serial log request failed"
    fi

    now=$(serial_console_epoch_seconds)
    if [[ "$now" -ge "$deadline" ]]; then
      continue
    fi
    sleep_seconds=$delay_seconds
    if [[ "$sleep_seconds" -gt "$((deadline - now))" ]]; then
      sleep_seconds=$((deadline - now))
    fi
    sleep "$sleep_seconds"
  done

  now=$(serial_console_epoch_seconds)
  elapsed=$((now - started_at))
  if $saw_real_content; then
    echo "::error::Azure serial log is missing expected FreeBSD output after" \
      "${elapsed}s and $attempt attempts; raw response saved to $boot_log_raw" >&2
  else
    echo "::error::Azure managed boot diagnostics did not return real serial" \
      "content after ${elapsed}s and $attempt attempts (last observation:" \
      "$observation); raw response saved to $boot_log_raw" >&2
  fi
  return 1
}

cleanup_on_exit() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]] &&
      az vm show --resource-group "$resource_group" --name "$vm_name" >/dev/null 2>&1; then
    if ! collect_failure_boot_log; then
      echo "::warning::Could not collect the failure-time Azure serial log" >&2
    fi
  fi
  rm -f -- "$vhd" "$private_key" "$private_key.pub"
  if ! cleanup_group; then
    status=1
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

resolve_azure_location_display_name() {
  local locations_path=$1 expected_location=$2
  if ! az account list-locations --output json >"$locations_path"; then
    echo "::error::Could not query Azure location metadata" >&2
    return 1
  fi
  python3 - "$locations_path" "$expected_location" <<'PY'
import json
import sys

path, expected = sys.argv[1:]
locations = json.load(open(path, encoding="utf-8"))
if not isinstance(locations, list):
    raise SystemExit("Azure location metadata is not a list")
matches = [
    location
    for location in locations
    if isinstance(location, dict)
    and isinstance(location.get("name"), str)
    and location["name"].casefold() == expected.casefold()
]
if len(matches) != 1:
    raise SystemExit(
        f"Azure location metadata contains {len(matches)} exact canonical "
        f"matches for {expected!r}"
    )
display_name = matches[0].get("displayName")
if not isinstance(display_name, str) or not display_name:
    raise SystemExit(f"Azure location {expected!r} has no display name")
print(display_name)
PY
}

validate_gallery_image_version_metadata() {
  python3 scripts/freebsd15_azure_metadata.py gallery-image-version "$@"
}

replication_epoch_seconds() {
  date +%s
}

boot_diagnostics_epoch_seconds() {
  date +%s
}

wait_for_managed_boot_diagnostics() {
  local timeout_seconds=${1:-180}
  local delay_seconds=${2:-5}
  local attempt deadline elapsed max_attempts now observation query_attempts=0
  local sleep_seconds started_at

  if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ||
        ! "$delay_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::Invalid Azure boot diagnostics timeout configuration" >&2
    return 1
  fi

  started_at=$(boot_diagnostics_epoch_seconds)
  deadline=$((started_at + timeout_seconds))
  max_attempts=$(((timeout_seconds + delay_seconds - 1) / delay_seconds + 1))
  observation="VM metadata has not been queried"

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    now=$(boot_diagnostics_epoch_seconds)
    if [[ "$attempt" -gt 1 && "$now" -ge "$deadline" ]]; then
      break
    fi

    query_attempts=$((query_attempts + 1))
    if az vm show \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --output json >"$vm_json" 2>"$vm_show_stderr"
    then
      if ! observation=$(
        python3 - "$vm_json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(document, dict):
    raise SystemExit("VM metadata is not an object")
profile = document.get("diagnosticsProfile")
if profile is None:
    print("pending: diagnosticsProfile is absent or null")
    raise SystemExit(0)
if not isinstance(profile, dict):
    raise SystemExit("VM diagnosticsProfile is not an object")
boot = profile.get("bootDiagnostics")
if boot is None:
    print("pending: bootDiagnostics is absent or null")
    raise SystemExit(0)
if not isinstance(boot, dict):
    raise SystemExit("VM bootDiagnostics is not an object")
storage_uri = boot.get("storageUri")
if storage_uri is not None:
    raise SystemExit(
        "managed boot diagnostics storageUri must be absent or null, "
        f"not {storage_uri!r}"
    )
enabled = boot.get("enabled")
if enabled is True:
    print("ready")
elif enabled in (None, False):
    print(f"pending: bootDiagnostics.enabled is {enabled!r}")
else:
    raise SystemExit(
        f"VM bootDiagnostics.enabled has invalid value {enabled!r}"
    )
PY
      )
      then
        echo "::error::Azure returned invalid managed boot diagnostics metadata;" \
          "response saved to $vm_json" >&2
        cat "$vm_json" >&2
        return 1
      fi
      if [[ "$observation" == ready ]]; then
        return
      fi
      if [[ "$observation" != pending:* ]]; then
        echo "::error::Unexpected managed boot diagnostics observation:" \
          "$observation; response saved to $vm_json" >&2
        cat "$vm_json" >&2
        return 1
      fi
    else
      observation="Azure VM metadata query failed"
    fi

    now=$(boot_diagnostics_epoch_seconds)
    if [[ "$now" -ge "$deadline" || "$attempt" -eq "$max_attempts" ]]; then
      break
    fi
    sleep_seconds=$delay_seconds
    if [[ "$sleep_seconds" -gt "$((deadline - now))" ]]; then
      sleep_seconds=$((deadline - now))
    fi
    sleep "$sleep_seconds"
  done

  now=$(boot_diagnostics_epoch_seconds)
  elapsed=$((now - started_at))
  echo "::error::Timed out after ${elapsed}s and ${query_attempts} attempts waiting for" \
    "managed boot diagnostics metadata (last observation: $observation);" \
    "VM metadata saved to $vm_json" >&2
  if [[ -s "$vm_show_stderr" ]]; then
    echo "::error::Latest Azure VM metadata API diagnostics:" >&2
    cat "$vm_show_stderr" >&2
  fi
  if [[ -s "$vm_json" ]]; then
    echo "::error::Latest Azure VM metadata response:" >&2
    cat "$vm_json" >&2
  fi
  return 1
}

wait_for_image_version_replication() {
  local timeout_seconds=${1:-1800}
  local delay_seconds=${2:-5}
  local max_delay_seconds=${3:-30}
  local aggregate_state deadline details elapsed now observation progress sleep_seconds
  local started_at state

  if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ||
        ! "$delay_seconds" =~ ^[1-9][0-9]*$ ||
        ! "$max_delay_seconds" =~ ^[1-9][0-9]*$ ||
        "$delay_seconds" -gt "$max_delay_seconds" ]]; then
    echo "::error::Invalid Azure image replication timeout/backoff configuration" >&2
    return 1
  fi

  started_at=$(replication_epoch_seconds)
  deadline=$((started_at + timeout_seconds))
  while true; do
    now=$(replication_epoch_seconds)
    if [[ -n ${state:-} && "$now" -ge "$deadline" ]]; then
      elapsed=$((now - started_at))
      echo "::error::Timed out after ${elapsed}s waiting for Azure image version" \
        "replication to $AZURE_LOCATION (last state=$state," \
        "aggregated=$aggregate_state, progress=$progress, details=$details);" \
        "status saved to $image_replication_json" >&2
      return 1
    fi

    if ! az sig image-version show \
      --resource-group "$resource_group" \
      --gallery-name "$gallery_name" \
      --gallery-image-definition "$image_definition_name" \
      --gallery-image-version "$image_version" \
      --expand ReplicationStatus \
      --output json >"$image_replication_json"
    then
      echo "::error::Could not query Azure image version replication status;" \
        "response saved to $image_replication_json" >&2
      return 1
    fi

    if ! observation=$(
      python3 - "$image_replication_json" "$AZURE_LOCATION" \
        "$azure_location_display_name" <<'PY'
import json
import sys

path, expected_region, expected_region_display_name = sys.argv[1:]
document = json.load(open(path, encoding="utf-8"))
replication = document.get("replicationStatus")
if not isinstance(replication, dict):
    raise SystemExit("image version replicationStatus is missing")
summary = replication.get("summary")
if not isinstance(summary, list):
    raise SystemExit("image version regional replication summary is missing")


def same_region(value):
    return isinstance(value, str) and value.casefold() in (
        expected_region.casefold(),
        expected_region_display_name.casefold(),
    )


matches = [
    entry
    for entry in summary
    if isinstance(entry, dict) and same_region(entry.get("region"))
]
if not matches:
    reported = [
        entry.get("region")
        for entry in summary
        if isinstance(entry, dict) and isinstance(entry.get("region"), str)
    ]
    raise SystemExit(
        f"replication status does not include target region {expected_region!r}; "
        f"reported regions: {reported!r}"
    )
if len(matches) != 1:
    raise SystemExit(
        f"replication status includes target region {expected_region!r} "
        f"{len(matches)} times"
    )

target = matches[0]
state = target.get("state")
if not isinstance(state, str) or not state:
    raise SystemExit("target region replication state is missing")
aggregate = replication.get("aggregatedState")
if aggregate is not None and not isinstance(aggregate, str):
    raise SystemExit("aggregated replication state is invalid")


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


print(
    "\x1f".join(
        (
            state,
            aggregate or "",
            compact(target.get("progress")),
            compact(target.get("details")),
        )
    )
)
PY
    )
    then
      echo "::error::Azure returned invalid regional image replication status;" \
        "response saved to $image_replication_json" >&2
      return 1
    fi
    IFS=$'\x1f' read -r state aggregate_state progress details <<<"$observation"

    if [[ "${state,,}" == completed ]]; then
      return
    fi
    if [[ "${state,,}" == failed || "${aggregate_state,,}" == failed ]]; then
      echo "::error::Azure image version replication to $AZURE_LOCATION failed" \
        "(state=$state, aggregated=$aggregate_state, progress=$progress," \
        "details=$details); status saved to $image_replication_json" >&2
      return 1
    fi
    case "${state,,}" in
      replicating|unknown) ;;
      *)
        echo "::error::Azure returned unexpected image replication state" \
          "$state for $AZURE_LOCATION (aggregated=$aggregate_state," \
          "progress=$progress, details=$details);" \
          "status saved to $image_replication_json" >&2
        return 1
        ;;
    esac

    now=$(replication_epoch_seconds)
    if [[ "$now" -ge "$deadline" ]]; then
      continue
    fi
    sleep_seconds=$delay_seconds
    if [[ "$sleep_seconds" -gt "$((deadline - now))" ]]; then
      sleep_seconds=$((deadline - now))
    fi
    sleep "$sleep_seconds"
    delay_seconds=$((delay_seconds * 2))
    if [[ "$delay_seconds" -gt "$max_delay_seconds" ]]; then
      delay_seconds=$max_delay_seconds
    fi
  done
}

azure_location_display_name=$(
  resolve_azure_location_display_name "$azure_locations_json" "$AZURE_LOCATION"
)

# Derive the fixed VHD
source_before=$(sha256sum "$asset" | awk '{print $1}')
test "$source_before" = "$qcow_sha256"
"$VMIZ" azure derive \
  --input-sha256 "$qcow_sha256" \
  --expected-virtual-size "$virtual_size" \
  "$asset" \
  "$vhd"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

# Structural VHD inspection
qemu-img info -f vpc --output=json "$vhd" >"$RESULT_DIR/vhd-info.json"
readarray -t vhd_geometry < <(
  python3 scripts/azure_vhd.py verify \
    --info "$RESULT_DIR/vhd-info.json" \
    --vhd "$vhd"
)
test "${#vhd_geometry[@]}" -eq 2
vhd_current_size=${vhd_geometry[0]}
vhd_bytes=${vhd_geometry[1]}
expected_vhd_current_size=$(((virtual_size + 1048575) / 1048576 * 1048576))
test "$vhd_current_size" -eq "$expected_vhd_current_size"
test "$vhd_bytes" -eq "$((vhd_current_size + 512))"
vhd_sha256=$(sha256sum "$vhd" | awk '{print $1}')
[[ "$vhd_sha256" =~ ^[0-9a-f]{64}$ ]]

# Confirm QCOW2 digest did not change after derivation
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

# Azure resource setup
if ! group_exists=$(az group exists --name "$resource_group" --output tsv); then
  echo "::error::Could not check for a resource-group collision"
  exit 1
fi
case "$group_exists" in
  true)
    echo "::error::Collision-resistant resource group already exists: $resource_group"
    exit 1
    ;;
  false) ;;
  *)
    echo "::error::Azure returned an invalid resource-group existence result"
    exit 1
    ;;
esac
printf '%s\n' "$resource_group" >"$STATE_FILE"
if ! az group create \
  --name "$resource_group" \
  --location "$AZURE_LOCATION" \
  --tags \
    vmiz-owner=freebsd15-release \
    "vmiz-run-id=$GITHUB_RUN_ID" \
    "vmiz-run-attempt=$GITHUB_RUN_ATTEMPT" \
    "vmiz-candidate=$CANDIDATE_KEY" \
  --output json >/dev/null
then
  echo "::error::Failed to create the persisted temporary resource group"
  exit 1
fi

# Validate VM SKU
az vm list-skus \
  --location "$AZURE_LOCATION" \
  --resource-type virtualMachines \
  --size "$AZURE_VM_SIZE" \
  --all \
  --output json >"$sku_json"
python3 - "$sku_json" "$AZURE_VM_SIZE" "$expected_azure_architecture" <<'PY'
import json
import sys

matches = [item for item in json.load(open(sys.argv[1], encoding="utf-8")) if item["name"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit("configured Azure VM SKU is absent or ambiguous in the configured location")
sku = matches[0]
location_restrictions = [
    restriction
    for restriction in sku.get("restrictions", [])
    if restriction.get("type") == "Location"
]
if location_restrictions:
    raise SystemExit(f"configured Azure VM SKU is location-restricted: {location_restrictions!r}")
capabilities = {item["name"]: item["value"] for item in sku.get("capabilities", [])}
if capabilities.get("CpuArchitectureType") != sys.argv[3]:
    raise SystemExit(f"SKU architecture mismatch: {capabilities.get('CpuArchitectureType')!r}")
if "V2" not in capabilities.get("HyperVGenerations", "").split(","):
    raise SystemExit("configured Azure VM SKU does not support Gen2")
PY

# Upload VHD to managed disk
az disk create \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --location "$AZURE_LOCATION" \
  --sku Standard_LRS \
  --upload-type Upload \
  --upload-size-bytes "$vhd_bytes" \
  --os-type Linux \
  --hyper-v-generation V2 \
  --architecture "$azure_image_architecture" \
  --output json >/dev/null
subscription_id=$(az account show --query id --output tsv)
[[ "$subscription_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
expected_disk_id="/subscriptions/$subscription_id/resourceGroups/$resource_group"
expected_disk_id+="/providers/Microsoft.Compute/disks/$disk_name"
disk_id=$(az disk show \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --query id \
  --output tsv)
test "${disk_id,,}" = "${expected_disk_id,,}"
upload_sas=$(grant_disk_write_access "$disk_id" 7200)
[[ "$upload_sas" == https://* ]]
echo "::add-mask::$upload_sas"
azcopy copy "$vhd" "$upload_sas" --blob-type PageBlob
az disk revoke-access \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --output json >/dev/null
upload_sas=

# Expand the OS disk to exercise root partition/pool growth
expanded_size_gib=$(((vhd_current_size + 1073741823) / 1073741824 + 2))
az disk update \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --size-gb "$expanded_size_gib" \
  --output json >/dev/null

# Validate the imported disk identity and matching architecture before using it.
az disk show \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --output json >"$disk_json"
disk_id=$(
  python3 scripts/freebsd15_azure_metadata.py managed-disk \
    "$disk_json" "$expected_disk_id" "$disk_name" "$resource_group" \
    "$AZURE_LOCATION" "$azure_image_architecture" "$expanded_size_gib"
)
test "${disk_id,,}" = "${expected_disk_id,,}"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"
test "$(sha256sum "$vhd" | awk '{print $1}')" = "$vhd_sha256"

# Create a private gallery and generalized Linux Gen2 image definition.
az sig create \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --location "$AZURE_LOCATION" \
  --output json >/dev/null
az sig show \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --output json >"$gallery_json"
expected_gallery_id="/subscriptions/$subscription_id/resourceGroups/$resource_group"
expected_gallery_id+="/providers/Microsoft.Compute/galleries/$gallery_name"
python3 scripts/freebsd15_azure_metadata.py gallery \
  "$gallery_json" "$expected_gallery_id" "$gallery_name" \
  "$resource_group" "$AZURE_LOCATION"

az sig image-definition create \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_definition_name" \
  --publisher "$image_publisher" \
  --offer "$image_offer" \
  --sku "$image_sku" \
  --os-type Linux \
  --os-state Generalized \
  --hyper-v-generation V2 \
  --architecture "$azure_image_architecture" \
  --location "$AZURE_LOCATION" \
  --output json >/dev/null
az sig image-definition show \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_definition_name" \
  --output json >"$image_definition_json"
expected_image_definition_id="$expected_gallery_id/images/$image_definition_name"
python3 - "$image_definition_json" "$expected_image_definition_id" \
  "$image_definition_name" "$resource_group" "$AZURE_LOCATION" \
  "$azure_image_architecture" "$image_publisher" "$image_offer" \
  "$image_sku" <<'PY'
import json
import sys

(
    path,
    expected_id,
    expected_name,
    expected_group,
    expected_location,
    expected_architecture,
    expected_publisher,
    expected_offer,
    expected_sku,
) = sys.argv[1:]
document = json.load(open(path, encoding="utf-8"))


def same(left, right):
    return isinstance(left, str) and left.casefold() == right.casefold()


if not same(document.get("id"), expected_id):
    raise SystemExit("Azure returned a different gallery image-definition identity")
if document.get("name") != expected_name:
    raise SystemExit("Azure returned a different gallery image-definition name")
resource_group = document.get("resourceGroup")
if resource_group not in (None, "") and not same(resource_group, expected_group):
    raise SystemExit("image definition is outside the owned temporary resource group")
if not same(document.get("location"), expected_location):
    raise SystemExit("gallery image-definition location mismatch")
if not same(document.get("type"), "Microsoft.Compute/galleries/images"):
    raise SystemExit("Azure returned a non-gallery-image-definition resource")
if document.get("provisioningState") != "Succeeded":
    raise SystemExit("gallery image-definition provisioning did not succeed")
if document.get("architecture") != expected_architecture:
    raise SystemExit("gallery image-definition architecture mismatch")
if document.get("hyperVGeneration") != "V2":
    raise SystemExit("gallery image definition is not Gen2")
if document.get("osType") != "Linux":
    raise SystemExit("gallery image-definition OS type mismatch")
if document.get("osState") != "Generalized":
    raise SystemExit("gallery image definition is not generalized")
identifier = document.get("identifier")
expected_identifier = {
    "publisher": expected_publisher,
    "offer": expected_offer,
    "sku": expected_sku,
}
if identifier != expected_identifier:
    raise SystemExit("gallery image-definition identifier mismatch")
PY

# Azure CLI names its managed-disk source option --os-snapshot.
image_version_id="$expected_image_definition_id/versions/$image_version"
az sig image-version create \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_definition_name" \
  --gallery-image-version "$image_version" \
  --location "$AZURE_LOCATION" \
  --os-snapshot "$disk_id" \
  --replication-mode Shallow \
  --replica-count 1 \
  --storage-account-type Standard_LRS \
  --target-regions "$AZURE_LOCATION=1=standard_lrs" \
  --no-wait \
  --output json >/dev/null
az sig image-version wait \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_definition_name" \
  --gallery-image-version "$image_version" \
  --created \
  --interval 10 \
  --timeout 1800 \
  --output none
az sig image-version show \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_definition_name" \
  --gallery-image-version "$image_version" \
  --output json >"$image_version_json"
validate_gallery_image_version_metadata \
  "$image_version_json" "$image_version_id" "$image_version" \
  "$resource_group" "$AZURE_LOCATION" "$azure_location_display_name" \
  "$disk_id" "$expanded_size_gib"
test "${image_version_id,,}" = \
  "${expected_image_definition_id,,}/versions/${image_version,,}"
wait_for_image_version_replication \
  "${AZURE_IMAGE_REPLICATION_TIMEOUT_SECONDS:-1800}" \
  "${AZURE_IMAGE_REPLICATION_INITIAL_DELAY_SECONDS:-5}" \
  "${AZURE_IMAGE_REPLICATION_MAX_DELAY_SECONDS:-30}"

# Create the matching-architecture VM from the exact gallery version with key-only SSH.
ssh-keygen -q -t ed25519 -N '' -C vmiz-azure-acceptance -f "$private_key"
az vm create \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --location "$AZURE_LOCATION" \
  --size "$AZURE_VM_SIZE" \
  --image "$image_version_id" \
  --admin-username "$admin_username" \
  --authentication-type ssh \
  --ssh-key-values "$private_key.pub" \
  --enable-agent false \
  --security-type Standard \
  --public-ip-sku Standard \
  --nsg-rule SSH \
  --output json >/dev/null
if ! az vm boot-diagnostics enable \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --output json >"$boot_diagnostics_enable_json" \
  2>"$boot_diagnostics_enable_stderr"
then
  echo "::error::Could not enable Azure managed boot diagnostics;" \
    "CLI response saved to $boot_diagnostics_enable_json and" \
    "$boot_diagnostics_enable_stderr" >&2
  if [[ -s "$boot_diagnostics_enable_stderr" ]]; then
    cat "$boot_diagnostics_enable_stderr" >&2
  fi
  if [[ -s "$boot_diagnostics_enable_json" ]]; then
    cat "$boot_diagnostics_enable_json" >&2
  fi
  exit 1
fi
wait_for_managed_boot_diagnostics \
  "${AZURE_BOOT_DIAGNOSTICS_TIMEOUT_SECONDS:-180}" \
  "${AZURE_BOOT_DIAGNOSTICS_POLL_SECONDS:-5}"
expected_vm_id="/subscriptions/$subscription_id/resourceGroups/$resource_group"
expected_vm_id+="/providers/Microsoft.Compute/virtualMachines/$vm_name"
vm_id=$(
  python3 scripts/freebsd15_azure_metadata.py vm \
    "$vm_json" "$expected_vm_id" "$vm_name" "$resource_group" \
    "$AZURE_LOCATION" "$AZURE_VM_SIZE" "$image_version_id" "$admin_username" \
    "$azure_image_architecture" "$expanded_size_gib"
)
test "${vm_id,,}" = "${expected_vm_id,,}"
public_ip=$(az vm show \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --show-details \
  --query publicIps \
  --output tsv)
[[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]]
test "$(az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query "instanceView.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
  --output tsv)" = ProvisioningState/succeeded
test "$(az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query "instanceView.statuses[?code=='PowerState/running'].code | [0]" \
  --output tsv)" = PowerState/running

ssh_options=(
  -i "$private_key"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ConnectionAttempts=1
  -o IdentitiesOnly=yes
  -o KbdInteractiveAuthentication=no
  -o PasswordAuthentication=no
  -o NumberOfPasswordPrompts=0
  -o PreferredAuthentications=publickey
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)
ssh_target="$admin_username@$public_ip"
guest_contract_stdout="$RESULT_DIR/guest-contract.stdout"
guest_contract_stderr="$RESULT_DIR/guest-contract.stderr"
guest_output_line_limit=200

print_bounded_guest_file() {
  local label=$1 path=$2 line_count
  printf -- '--- %s (first %s lines) ---\n' \
    "$label" "$guest_output_line_limit" >&2
  if [[ ! -s "$path" ]]; then
    echo "[empty]" >&2
    return
  fi
  sed -n "1,${guest_output_line_limit}p" "$path" >&2
  line_count=$(wc -l <"$path")
  if (( line_count > guest_output_line_limit )); then
    printf '[truncated: %s total lines]\n' "$line_count" >&2
  fi
}

run_guest_contract() {
  local stdout_path=$1 stderr_path=$2 status
  shift 2
  if ssh "${ssh_options[@]}" "$ssh_target" "$@" \
      >"$stdout_path" 2>"$stderr_path"
  then
    return
  else
    status=$?
  fi
  printf '::error::Remote guest contract SSH failed with status %s\n' \
    "$status" >&2
  if ! print_bounded_guest_file "remote guest stdout" "$stdout_path"; then
    echo "::warning::Could not print captured remote guest stdout" >&2
  fi
  if ! print_bounded_guest_file "remote guest stderr" "$stderr_path"; then
    echo "::warning::Could not print captured remote guest stderr" >&2
  fi
  return "$status"
}

wait_for_ssh() {
  for _ in {1..180}; do
    if ssh "${ssh_options[@]}" "$ssh_target" true >/dev/null 2>&1; then
      return
    fi
    sleep 5
  done
  echo "::error::Timed out waiting for key-only SSH"
  return 1
}

reboot_and_reconnect() {
  ssh "${ssh_options[@]}" "$ssh_target" 'sudo shutdown -r now' >/dev/null 2>&1 || true
  sleep 15
  for _ in {1..180}; do
    if ssh "${ssh_options[@]}" "$ssh_target" true >/dev/null 2>&1; then
      return
    fi
    sleep 5
  done
  echo "::error::Guest did not reboot and reconnect"
  return 1
}

wait_for_poweroff() {
  local power_state
  for _ in {1..60}; do
    power_state=$(az vm get-instance-view \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" \
      --output tsv)
    case "$power_state" in
      PowerState/stopped|PowerState/deallocated) return ;;
    esac
    sleep 5
  done
  echo "::error::Guest did not complete a clean shutdown"
  return 1
}

# --- CONTRACT: matching-architecture-gen2 ---
# (Gen2 and architecture are validated across SKU, source disk, image, and VM.)

# --- CONTRACT: key-only-ssh ---
wait_for_ssh
if ssh \
  -o BatchMode=yes \
  -o ConnectTimeout=5 \
  -o PreferredAuthentications=none \
  -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "$ssh_target" true >/dev/null 2>&1; then
  echo "::error::SSH unexpectedly accepted a connection without the generated key"
  exit 1
fi

# Capture pre-reboot identity markers
pre_reboot_hostkey=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'cat /etc/ssh/ssh_host_ed25519_key.pub')
pre_reboot_hostuuid=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'sudo sysctl -n kern.hostuuid')
pre_reboot_storage_identity=
if [[ "$FILESYSTEM" == zfs ]]; then
  pre_reboot_storage_identity=$(ssh "${ssh_options[@]}" "$ssh_target" \
    'zpool get -Hp -o value guid zroot')
fi

# --- SHARED CONTRACTS: agent-ready, hn0-dhcp, root-growth, gpt-healthy ---
# --- FILESYSTEM CONTRACTS: ufs-root / zfs-root and their growth/health state ---
run_guest_contract "$guest_contract_stdout" "$guest_contract_stderr" \
  "/bin/sh -s -- '$vhd_current_size' '$runtime_architecture' '$FILESYSTEM'" <<'GUEST'
set -eu
original_size=$1
runtime_arch=$2
expected_filesystem=$3
guest_phase=initialization
guest_check="initialize guest contract"
root_device=
rootfs=
root_provider=
disk=
root_partition_size=
root_filesystem_kib=
root_pool=
pool_size=

privileged_diskinfo() {
  sudo -n diskinfo "$@"
}

privileged_gpart() {
  sudo -n gpart "$@"
}

privileged_glabel_status() {
  sudo -n glabel status
}

privileged_mdconfig() {
  sudo -n mdconfig "$@"
}

partition_disk_for_provider() {
  partition_provider=$1
  partition_disk=$(printf '%s\n' "$partition_provider" |
    sed -E 's/(p|s)[0-9]+$//')
  if [ -z "$partition_disk" ] || [ "$partition_disk" = "$partition_provider" ] ||
      ! printf '%s\n' "$partition_provider" |
        grep -Eq '^[[:alnum:]_.-]+(p|s)[0-9]+$'; then
    echo "provider is not an exact partition provider: $partition_provider" >&2
    return 1
  fi
  printf '%s\n' "$partition_disk"
}

resolve_guest_provider() {
  case "$1" in
    /dev/*) requested_provider=${1#/dev/} ;;
    /*)
      echo "guest provider is malformed: $1" >&2
      return 1
      ;;
    *) requested_provider=$1 ;;
  esac
  if [ -z "$requested_provider" ]; then
    echo "guest provider is malformed: $1" >&2
    return 1
  fi
  case "$requested_provider" in
    */*)
      resolved_provider=$(
        privileged_glabel_status |
          awk -v requested="$requested_provider" '
            NR == 1 {
              if (NF != 3 || $1 != "Name" || $2 != "Status" ||
                  $3 != "Components") {
                exit 2
              }
              next
            }
            NF == 0 {
              next
            }
            NF != 3 {
              exit 3
            }
            $1 == requested {
              if ($3 == "" || $3 ~ /\//) {
                exit 3
              }
              print $3
              matches++
            }
            END {
              if (matches != 1) {
                exit 4
              }
            }
          '
      ) || {
        echo "GEOM label did not resolve exactly once: $requested_provider" >&2
        return 1
      }
      partition_disk_for_provider "$resolved_provider" >/dev/null || {
        echo "GEOM label does not resolve to a partition: $requested_provider" >&2
        return 1
      }
      printf '%s\n' "$resolved_provider"
      ;;
    *)
      if ! printf '%s\n' "$requested_provider" |
          grep -Eq '^[[:alnum:]_.-]+$'; then
        echo "guest provider is malformed: $1" >&2
        return 1
      fi
      printf '%s\n' "$requested_provider"
      ;;
  esac
}

begin_guest_phase() {
  guest_phase=$1
  guest_check=$2
  printf 'guest contract phase: %s\n' "$guest_phase"
}

guest_observation() {
  observation=$1
  shift
  printf '%s\n' "--- guest observation: $observation (first 40 lines) ---"
  "$@" 2>&1 | sed -n '1,40p'
}

guest_contract_diagnostics() {
  set +e
  diagnostic_root_device=$root_device
  diagnostic_rootfs=$rootfs
  diagnostic_disk=$disk
  diagnostic_root_provider=
  if [ -z "$diagnostic_root_device" ]; then
    diagnostic_root_device=$(mount -p | awk '$2 == "/" { print $1 }')
  fi
  if [ -z "$diagnostic_rootfs" ]; then
    diagnostic_rootfs=$(mount -p | awk '$2 == "/" { print $3 }')
  fi
  if [ "$diagnostic_rootfs" = ufs ]; then
    if [ -n "$root_provider" ]; then
      diagnostic_root_provider=$root_provider
    elif [ -n "$diagnostic_root_device" ]; then
      diagnostic_root_provider=$(resolve_guest_provider "$diagnostic_root_device")
    fi
    if [ -z "$diagnostic_disk" ] && [ -n "$diagnostic_root_provider" ]; then
      diagnostic_disk=$(partition_disk_for_provider "$diagnostic_root_provider")
    fi
  elif [ -z "$diagnostic_disk" ] && [ "$diagnostic_rootfs" = zfs ]; then
    diagnostic_root_provider=$(zpool status -LP "${diagnostic_root_device%%/*}" |
      awk '/\/dev\// { sub("^/dev/", "", $1); print $1 }')
    if [ "$(printf '%s\n' "$diagnostic_root_provider" | sed '/^$/d' | wc -l)" -eq 1 ]; then
      diagnostic_root_provider=$(resolve_guest_provider "$diagnostic_root_provider")
      diagnostic_disk=$(partition_disk_for_provider "$diagnostic_root_provider")
    fi
  fi
  printf '%s\n' \
    "guest contract context: phase=$guest_phase check=$guest_check" \
    "guest storage context: original_size=$original_size root_device=$diagnostic_root_device rootfs=$diagnostic_rootfs root_provider=$diagnostic_root_provider disk=$diagnostic_disk" \
    "guest size context: root_partition_size=$root_partition_size root_filesystem_kib=$root_filesystem_kib root_pool=$root_pool pool_size=$pool_size"
  guest_observation architecture uname -a
  guest_observation architecture-sysctl sysctl -n hw.machine_arch
  guest_observation sshd-settings /bin/sh -c \
    "sudo sshd -T 2>&1 | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication) '"
  guest_observation agent-processes /bin/sh -c \
    "ps axww -o pid=,ppid=,command= | grep -E '[w]aagent|[a]zure-agent'"
  guest_observation agent-service service azure_agent status
  guest_observation network-interfaces ifconfig -a
  guest_observation mounts mount -p
  guest_observation root-filesystem df -k /
  if [ -n "$diagnostic_root_provider" ] && [ "$diagnostic_rootfs" = ufs ]; then
    guest_observation root-device privileged_diskinfo \
      "/dev/$diagnostic_root_provider"
  elif [ "$diagnostic_rootfs" = zfs ]; then
    guest_observation zpool-list zpool list -Hp
    guest_observation zpool-status zpool status -LP
  fi
  if [ -n "$diagnostic_disk" ]; then
    guest_observation gpart-show privileged_gpart show "$diagnostic_disk"
    guest_observation gpart-status privileged_gpart status -s "$diagnostic_disk"
  fi
  guest_observation swapinfo swapinfo -k
  guest_observation mdconfig privileged_mdconfig -lv
}

guest_contract_exit() {
  status=$?
  trap - EXIT
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  line=${LINENO:-unknown}
  printf 'guest contract failed: phase=%s check=%s status=%s remote_line=%s\n' \
    "$guest_phase" "$guest_check" "$status" "$line" >&2
  guest_contract_diagnostics >&2
  exit "$status"
}
trap guest_contract_exit EXIT

# Validate runtime architecture
begin_guest_phase runtime-architecture "read hw.machine_arch"
hw_machine=$(sysctl -n hw.machine_arch)
guest_check="match hw.machine_arch to release architecture"
test "$hw_machine" = "$runtime_arch"

# key-only-ssh: verify sshd configuration
begin_guest_phase sshd-policy "read effective sshd configuration"
sshd_config=$(sudo sshd -T 2>/dev/null)
guest_check="disable SSH password authentication"
printf '%s\n' "$sshd_config" | grep -iq '^passwordauthentication no'
guest_check="disable SSH keyboard-interactive authentication"
printf '%s\n' "$sshd_config" | grep -iq '^kbdinteractiveauthentication no'

# No default freebsd account, root is locked
begin_guest_phase account-policy "reject default freebsd account"
! id freebsd >/dev/null 2>&1
guest_check="read root password field"
root_pw=$(sudo awk -F: '$1=="root"{print $2}' /etc/master.passwd)
guest_check="require locked root account"
case "$root_pw" in
  '*LOCKED*'|'*'|'!*'|'!') ;;
  *) echo "root account is not locked" >&2; exit 1 ;;
esac

# agent-ready: Azure Agent (waagent or azure-agent) is running
begin_guest_phase azure-agent-ready "find a running Azure Agent"
if ! pgrep -f 'python.*waagent' >/dev/null 2>&1 && \
   ! service azure_agent status >/dev/null 2>&1 && \
   ! pgrep azure-agent >/dev/null 2>&1; then
  echo "Azure Agent is not running" >&2
  exit 1
fi

# hn0-dhcp: network interface has an address via DHCP
begin_guest_phase network-dhcp "select the Azure network interface"
if ifconfig hn0 >/dev/null 2>&1; then
  guest_check="require an IPv4 address on hn0"
  ifconfig hn0 | grep -q 'inet '
elif ifconfig eth0 >/dev/null 2>&1; then
  guest_check="require an IPv4 address on eth0"
  ifconfig eth0 | grep -q 'inet '
else
  # Any Hyper-V NIC
  guest_check="find a Hyper-V network interface"
  nic=$(ifconfig -l | tr ' ' '\n' | grep -E '^(hn|storvsc)' | head -1)
  test -n "$nic"
  guest_check="require an IPv4 address on the Hyper-V network interface"
  ifconfig "$nic" | grep -q 'inet '
fi

begin_guest_phase root-filesystem "identify the root device"
root_device=$(mount -p | awk '$2 == "/" { print $1 }')
guest_check="identify the root filesystem type"
rootfs=$(mount -p | awk '$2 == "/" { print $3 }')
guest_check="require a nonempty root device"
test -n "$root_device"
guest_check="match the expected root filesystem"
test "$rootfs" = "$expected_filesystem"

case "$expected_filesystem" in
  ufs)
    # ufs-root and UFS growth: both the partition provider and filesystem must
    # have expanded beyond the exact candidate's original virtual size.
    begin_guest_phase ufs-root-growth "require a UFS root fstab entry"
    grep -Eq '^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]' /etc/fstab
    guest_check="resolve the UFS root provider"
    root_provider=$(resolve_guest_provider "$root_device")
    guest_check="identify the UFS root disk"
    disk=$(partition_disk_for_provider "$root_provider")
    guest_check="read the UFS root partition size"
    root_partition_size=$(privileged_diskinfo "/dev/$root_provider" |
      awk '{ print $3 }')
    guest_check="read the UFS root filesystem size"
    root_filesystem_kib=$(df -k / | awk 'END { print $2 }')
    guest_check="require UFS root partition growth"
    test "$root_partition_size" -gt "$original_size"
    guest_check="require UFS root filesystem growth"
    test "$root_filesystem_kib" -gt "$((original_size / 1024))"
    ;;
  zfs)
    # zfs-root, pool health, autoexpand, growth, and absence of swap zvols.
    begin_guest_phase zfs-root-health "identify the ZFS root pool"
    root_pool=${root_device%%/*}
    guest_check="require zroot as the root pool"
    test "$root_pool" = zroot
    guest_check="require a healthy ZFS root pool"
    test "$(zpool status -x "$root_pool")" = "pool '$root_pool' is healthy"
    guest_check="require ZFS root pool autoexpand"
    test "$(zpool get -H -o value autoexpand "$root_pool")" = on
    guest_check="read the ZFS root pool size"
    pool_size=$(zpool list -Hp -o size "$root_pool")
    guest_check="require ZFS root pool growth"
    test "$pool_size" -gt "$original_size"
    guest_check="identify the single ZFS root provider"
    root_provider=$(zpool status -LP "$root_pool" |
      awk '/\/dev\// { sub("^/dev/", "", $1); print $1 }')
    test "$(printf '%s\n' "$root_provider" | sed '/^$/d' | wc -l)" -eq 1
    guest_check="resolve the ZFS root provider"
    root_provider=$(resolve_guest_provider "$root_provider")
    guest_check="identify the ZFS root disk"
    disk=$(partition_disk_for_provider "$root_provider")
    guest_check="reject ZFS swap volumes"
    test -z "$(zfs list -H -o name,org.freebsd:swap -t volume |
      awk '$2 == "on" { print $1 }')"
    ;;
  *)
    echo "unsupported root filesystem: $expected_filesystem" >&2
    exit 1
    ;;
esac

# gpt-healthy: the OS disk has a recovered GPT and every provider is healthy.
begin_guest_phase gpt-health "require a nonempty OS disk"
test -n "$disk"
guest_check="reject corrupt GPT metadata"
! privileged_gpart show "$disk" | grep -q CORRUPT
guest_check="require every GPT provider status to be OK"
test "$(privileged_gpart status -s "$disk" |
  awk '{ print $2 }' | sort -u)" = OK

# no-os-disk-swap: positively identify every swap as resource-disk-backed.
begin_guest_phase swap-policy "define resource-disk provider validation"
require_resource_disk_provider() {
  provider=$1
  resource_disk=$(partition_disk_for_provider "$provider") || return 1
  if [ "$resource_disk" = "$disk" ]; then
    echo "swap is not backed by a resource-disk partition: $provider" >&2
    return 1
  fi
  privileged_diskinfo "/dev/$resource_disk" >/dev/null
}

guest_check="enumerate configured swap devices"
swapinfo -k | awk 'NR > 1 { print $1 }' | while IFS= read -r swap_device; do
  test -n "$swap_device" || continue
  guest_check="resolve swap provider $swap_device"
  swap_provider=$(resolve_guest_provider "$swap_device")
  case "$swap_provider" in
    md[0-9]*)
      md_unit=${swap_provider#md}
      guest_check="resolve md-backed swap vnode $swap_device"
      md_backing=$(privileged_mdconfig -lv -u "$md_unit" |
        awk -F '	' '$2 == "vnode" { print $4; exit }')
      if [ -z "$md_backing" ] || [ ! -f "$md_backing" ]; then
        echo "swap md provider is not a resolvable vnode: $swap_device" >&2
        exit 1
      fi
      guest_check="identify md-backed swap mount $swap_device"
      md_backing_mount=$(df -k "$md_backing" | awk 'END { print $6 }')
      guest_check="identify md-backed swap device $swap_device"
      md_backing_device=$(df -k "$md_backing" | awk 'END { print $1 }')
      if [ "$md_backing_mount" = / ] || [ "${md_backing_device#/dev/}" = "$md_backing_device" ]; then
        echo "swap vnode is backed by the OS/root filesystem: $md_backing" >&2
        exit 1
      fi
      guest_check="resolve md-backed swap provider $swap_device"
      md_backing_provider=$(resolve_guest_provider "$md_backing_device")
      guest_check="require resource-disk backing for $swap_device"
      require_resource_disk_provider "$md_backing_provider"
      ;;
    *p[0-9]*|*s[0-9]*)
      guest_check="require resource-disk backing for $swap_device"
      require_resource_disk_provider "$swap_provider"
      ;;
    *)
      echo "swap provider is not positively identified as resource-disk-backed: $swap_device" >&2
      exit 1
      ;;
  esac
done
GUEST

# --- CONTRACT: reboot-reconnect ---
reboot_and_reconnect

# --- CONTRACT: serial-console ---
require_serial_console_log

# --- CONTRACT: instance-identity ---
post_reboot_hostkey=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'cat /etc/ssh/ssh_host_ed25519_key.pub')
post_reboot_hostuuid=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'sudo sysctl -n kern.hostuuid')
test "$pre_reboot_hostkey" = "$post_reboot_hostkey"
test "$pre_reboot_hostuuid" = "$post_reboot_hostuuid"

if [[ "$FILESYSTEM" == zfs ]]; then
  post_reboot_storage_identity=$(ssh "${ssh_options[@]}" "$ssh_target" \
    'zpool get -Hp -o value guid zroot')
  test "$pre_reboot_storage_identity" = "$post_reboot_storage_identity"
  ssh "${ssh_options[@]}" "$ssh_target" \
    'test "$(zpool status -x zroot)" = "pool '\''zroot'\'' is healthy"; test "$(zpool get -H -o value autoexpand zroot)" = on'
else
  ssh "${ssh_options[@]}" "$ssh_target" \
    'test "$(mount -p | awk '\''$2 == "/" { print $3 }'\'')" = ufs'
fi

# Clean shutdown
ssh "${ssh_options[@]}" "$ssh_target" 'sudo shutdown -p now' >/dev/null 2>&1 || true
wait_for_poweroff

# --- Generate result ---
azure_accepted_sha256=$(sha256sum "$asset" | awk '{print $1}')
test "$azure_accepted_sha256" = "$qcow_sha256"
readarray -t result_candidate < <(
  validate_candidate_binding
)
test "${#result_candidate[@]}" -eq 5
test "${result_candidate[0]}" = "$qcow_sha256"
test "${result_candidate[1]}" = "$qcow_bytes"
test "${result_candidate[2]}" = "$qcow_allocated_size"
test "${result_candidate[3]}" = "$virtual_size"
test "${result_candidate[4]}" = "$candidate_architecture"

shared_contracts_before_storage="matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp,serial-console"
shared_contracts_after_storage="root-growth,gpt-healthy,reboot-reconnect,instance-identity"
case "$FILESYSTEM" in
  zfs)
    # Keep the established ZFS/full result contract byte-for-byte stable.
    filesystem_contracts="zfs-root,zpool-healthy"
    ;;
  ufs)
    filesystem_contracts="ufs-root,ufs-root-partition-growth,ufs-root-filesystem-growth,no-os-disk-swap"
    ;;
esac
contracts="$shared_contracts_before_storage,$filesystem_contracts,$shared_contracts_after_storage"

python3 scripts/freebsd15_release.py azure-result \
  --manifest "$manifest" \
  --asset "$asset" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$AZURE_LOCATION" \
  --vm-size "$AZURE_VM_SIZE" \
  --resource-group "$resource_group" \
  --vhd-sha256 "$vhd_sha256" \
  --vhd-bytes "$vhd_bytes" \
  --vhd-current-size "$vhd_current_size" \
  --contracts "$contracts" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output "$RESULT_DIR/azure-result.json"

# Final source-digest assertion
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"
test "$(sha256sum "$vhd" | awk '{print $1}')" = "$vhd_sha256"

{
  echo "### Azure acceptance: $ASSET_NAME"
  echo
  echo "- QCOW2 SHA-256: \`$qcow_sha256\`"
  echo "- Derived VHD: \`$vhd_sha256\`; current $vhd_current_size bytes;" \
    "file $vhd_bytes bytes (not retained or published)"
  echo "- Azure: \`$AZURE_LOCATION\` / \`$AZURE_VM_SIZE\`"
  echo "- Temporary managed disk, gallery image version, and VM: owned resource-group cleanup"
  echo "- Contracts: $contracts"
  echo "- Status: success"
} >>"$GITHUB_STEP_SUMMARY"
