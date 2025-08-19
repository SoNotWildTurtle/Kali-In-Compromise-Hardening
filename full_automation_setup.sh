#!/bin/bash
# full_automation_setup.sh - orchestrate secure dev environment, IDS setup, and ISO build
set -euo pipefail

# Prompt for build options so running the script alone is sufficient
read -rp "Build mode (installer/live) [installer]: " MODE
MODE=${MODE:-installer}

DEFAULT_ISO="$(pwd)/kali-custom.iso"
read -rp "Output ISO path [${DEFAULT_ISO}]: " OUT_ISO
OUT_ISO=${OUT_ISO:-$DEFAULT_ISO}

read -rp "Working directory [/tmp/kali-auto-build]: " WORKDIR
WORKDIR=${WORKDIR:-/tmp/kali-auto-build}

read -rp "Enter Kali username: " KALI_USER
read -srp "Enter Kali password: " KALI_PASS; echo
read -rp "Enter guest username: " GUEST_USER
read -srp "Enter guest password: " GUEST_PASS; echo

# Install secure development environment
if [ -x ./secure_dev_env.sh ]; then
    ./secure_dev_env.sh
fi

# Prepare neural network IDS components
if [ -x ./setup_nn_ids.sh ]; then
    ./setup_nn_ids.sh
fi

# Build custom ISO
if [ -x ./build_custom_iso.sh ]; then
    KALI_USERNAME="$KALI_USER" KALI_PASSWORD="$KALI_PASS" \
    GUEST_USERNAME="$GUEST_USER" GUEST_PASSWORD="$GUEST_PASS" \
    ./build_custom_iso.sh "$MODE" "$OUT_ISO" "$WORKDIR"
else
    echo "build_custom_iso.sh not found" >&2
    exit 1
fi
