#!/usr/bin/env bash
# Local, offline-signed end-to-end reproduction of the protected Ubuntu 26.04
# release build. It exercises the exact release builder entrypoint
# (`zig build generalized-ubuntu2604`) -- base-image acquisition and signature
# verification, embedded debz customize, native UKI assembly, UKI signing, and
# standalone zstd QCOW2 finalization -- then validates the finalized candidate
# the same way .github/workflows/ubuntu2604-release.yml does.
#
# The only intentional deviation from the release workflow is the signing
# identity: instead of the Azure Trusted Signing command
# (`--uki-sign-command`), this driver signs with a safe, public, test-only
# self-signed key/cert committed under tests/fixtures/ubuntu2604-local-signing/.
# This lets the corrected candidate be built and validated locally BEFORE any
# protected release build is dispatched, per the release-gate requirement.
#
# Usage:
#   ZIG=/path/to/zig-0.16.0 \
#   SEED_CACHE=/home/you/.cache/zig \
#   scripts/ubuntu2604_local_e2e.sh [x86_64|aarch64]
#
# Notes:
#   * Requires passwordless sudo: the debz customize stage runs inside a
#     privileged offline-root mount namespace (euid 0).
#   * A full build is only feasible for a guest architecture whose systemd-boot
#     EFI stub is installed on the host. On an x86_64 host without the aarch64
#     stub, use the deterministic resolve->customize integration test for arm64
#     (zig build test-generalized-ubuntu2604) instead.
set -euo pipefail

ARCH="${1:-x86_64}"
case "$ARCH" in
  x86_64 | aarch64) ;;
  *) echo "unsupported architecture: $ARCH (expected x86_64 or aarch64)" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

: "${ZIG:?set ZIG to the zig 0.16.0 binary used to build vmiz}"
VIRTUAL_SIZE="${VIRTUAL_SIZE:-5368709120}"
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/ubuntu2604-local-signing"
CERT="$FIXTURE_DIR/signing-cert.pem"
KEY="$FIXTURE_DIR/signing-key.pem"
CERT_SHA256="${CERT_SHA256:-74556e6a0b540eb0ed5a49d9e75a003987447699df59f1d68456548c47dc8009}"

OUT_ROOT="${OUT_ROOT:-$REPO_ROOT/.scratch/local-e2e/$ARCH}"
WORK_DIR="$OUT_ROOT/work"
BUNDLE_DIR="$OUT_ROOT/bundle"
ASSET_NAME="Ubuntu-26.04-$ARCH.qcow2"
OUTPUT="$BUNDLE_DIR/$ASSET_NAME"
PROVENANCE_DIR="$BUNDLE_DIR/internal-provenance"

test -f "$CERT" || { echo "missing signing certificate fixture: $CERT" >&2; exit 3; }
test -f "$KEY" || { echo "missing signing key fixture: $KEY" >&2; exit 3; }

# Isolated in-tree global cache so the privileged (sudo) build never writes into
# a shared user cache. Seed it once from the caller's cache to avoid re-fetching
# pinned dependencies under root.
export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/.zig-global-cache"
unset ZIG_LOCAL_CACHE_DIR || true
if [ ! -d "$ZIG_GLOBAL_CACHE_DIR" ]; then
  if [ -n "${SEED_CACHE:-}" ] && [ -d "$SEED_CACHE" ]; then
    echo "seeding in-tree zig cache from $SEED_CACHE"
    cp -a "$SEED_CACHE" "$ZIG_GLOBAL_CACHE_DIR"
  else
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
  fi
fi

rm -rf -- "$BUNDLE_DIR"
mkdir -p "$PROVENANCE_DIR" "$WORK_DIR"
build_log="$WORK_DIR/build.log"

echo "== building $ASSET_NAME (local self-signed UKI) =="
sudo -E "$ZIG" build \
  -Dubuntu2604-arch="$ARCH" \
  generalized-ubuntu2604 -- \
  --work-dir "$WORK_DIR" \
  --provenance-dir "$PROVENANCE_DIR" \
  --output "$OUTPUT" \
  --size "$VIRTUAL_SIZE" \
  --uki-signing-certificate "$CERT" \
  --uki-signing-certificate-sha256 "$CERT_SHA256" \
  --uki-signing-key "$KEY" \
  2>&1 | tee "$build_log"

sudo chown -R "$(id -u):$(id -g)" "$WORK_DIR" "$BUNDLE_DIR" "$ZIG_GLOBAL_CACHE_DIR" 2>/dev/null || true
cp "$build_log" "$PROVENANCE_DIR/build.log"

echo "== validating finalized candidate =="
VMIZ="$REPO_ROOT/zig-out/bin/vmiz"
test -f "$OUTPUT"
test -x "$VMIZ"
"$VMIZ" check "$OUTPUT"
"$VMIZ" info --output=json "$OUTPUT" > "$PROVENANCE_DIR/image-info.json"
python3 - "$PROVENANCE_DIR/image-info.json" "$VIRTUAL_SIZE" <<'PY'
import json
import sys

info = json.load(open(sys.argv[1], encoding="utf-8"))
if info.get("format") != "qcow2":
    raise SystemExit("candidate is not QCOW2")
if info.get("virtual-size") != int(sys.argv[2]):
    raise SystemExit("candidate virtual size is not exactly the requested size")
if info.get("backing-filename") or info.get("full-backing-filename"):
    raise SystemExit("candidate has a backing file")
data = (info.get("format-specific") or {}).get("data") or {}
if data.get("compression-type") != "zstd":
    raise SystemExit("candidate does not use zstd cluster compression")
print("candidate is a standalone zstd QCOW2 at the exact requested virtual size")
PY

digest=$(sha256sum "$OUTPUT" | awk '{print $1}')
[[ "$digest" =~ ^[0-9a-f]{64}$ ]]
printf '%s\n' "$digest" > "$PROVENANCE_DIR/build-validated-digest"

echo "== verifying UKI signature against the enrolled local certificate =="
case "$ARCH" in
  x86_64) UKI_PATH="$WORK_DIR/BOOTX64.EFI" ;;
  aarch64) UKI_PATH="$WORK_DIR/BOOTAA64.EFI" ;;
esac
if [ -f "$UKI_PATH" ]; then
  "$VMIZ" uki verify --certificate "$CERT" "$UKI_PATH"
  echo "signed UKI verifies against the local certificate"
else
  echo "note: signed UKI not retained at $UKI_PATH; builder already self-verified it"
fi

echo
echo "OK: $ASSET_NAME"
echo "  size (bytes): $(stat -c %s "$OUTPUT")"
echo "  sha256:       $digest"
echo "  info json:    $PROVENANCE_DIR/image-info.json"
echo "  build log:    $PROVENANCE_DIR/build.log"
