#!/usr/bin/env bash
# MINC - Static packaging tests for firstboot release-gate bundle manifest.
# Defensive validation only: confirms custom ISO packaging and documentation contracts.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_release_gate_bundle_manifest.py

if ! grep -q '"firstboot_release_gate_bundle_manifest.py"' build_custom_iso.sh; then
  echo 'expected firstboot_release_gate_bundle_manifest.py to be packaged into the custom ISO' >&2
  exit 1
fi

if ! grep -q 'firstboot_release_gate_bundle_manifest.py' docs/firstboot_release_gate_bundle_manifest.md; then
  echo 'expected bundle manifest documentation to name the packaged helper' >&2
  exit 1
fi

if ! grep -q 'Remove the helper from custom ISO packaging' docs/firstboot_release_gate_bundle_manifest.md; then
  echo 'expected rollback guidance to cover custom ISO packaging removal' >&2
  exit 1
fi

if ! grep -q 'firstboot_release_gate_bundle_manifest.py' CHANGELOG.md; then
  echo 'expected changelog to mention firstboot release-gate bundle manifest packaging' >&2
  exit 1
fi

echo '[static-check] firstboot release-gate bundle manifest packaging passed static checks'
