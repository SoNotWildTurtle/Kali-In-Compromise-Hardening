#!/bin/bash
# full_automation_setup.sh - orchestrate secure dev environment, IDS setup, and ISO build
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Log all actions to a timestamped file in the current directory for auditing
LOGFILE="$(pwd)/press_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Logging to $LOGFILE"

usage() {
    echo "Usage: $0 [-c config] [-m installer|live] [-o output_iso] [-w workdir] [-u kali_user] [-p kali_pass] [-g guest_user] [-s guest_pass] [-k] [-a]" >&2
    echo "       -a : run non-interactively; all options must be provided via config or CLI" >&2
    echo "Environment: PRESS_CONF can specify a config file" >&2
}

ENV_MODE=${MODE:-}
ENV_OUT=${OUT_ISO:-}
ENV_WORK=${WORKDIR:-}
ENV_KALI_USER=${KALI_USER:-}
ENV_KALI_PASS=${KALI_PASS:-}
ENV_GUEST_USER=${GUEST_USER:-}
ENV_GUEST_PASS=${GUEST_PASS:-}

MODE=""
OUT_ISO=""
WORKDIR=""
KALI_USER=""
KALI_PASS=""
GUEST_USER=""
GUEST_PASS=""
KEEP_WORKDIR=0
AUTO=0

# Allow PRESS_CONF to override default config path
CONFIG_FILE="${PRESS_CONF:-press.conf}"

# Parse all command-line options but defer config sourcing so CLI values override
CLI_MODE=""
CLI_OUT=""
CLI_WORK=""
CLI_KALI_USER=""
CLI_KALI_PASS=""
CLI_GUEST_USER=""
CLI_GUEST_PASS=""

while getopts "c:m:o:w:u:p:g:s:kah" opt; do
    case "$opt" in
        c) CONFIG_FILE=$OPTARG ;;
        m) CLI_MODE=$OPTARG ;;
        o) CLI_OUT=$OPTARG ;;
        w) CLI_WORK=$OPTARG ;;
        u) CLI_KALI_USER=$OPTARG ;;
        p) CLI_KALI_PASS=$OPTARG ;;
        g) CLI_GUEST_USER=$OPTARG ;;
        s) CLI_GUEST_PASS=$OPTARG ;;
        k) KEEP_WORKDIR=1 ;;
        a) AUTO=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND-1))

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Apply environment variable overrides
MODE=${ENV_MODE:-${MODE}}
OUT_ISO=${ENV_OUT:-${OUT_ISO}}
WORKDIR=${ENV_WORK:-${WORKDIR}}
KALI_USER=${ENV_KALI_USER:-${KALI_USER}}
KALI_PASS=${ENV_KALI_PASS:-${KALI_PASS}}
GUEST_USER=${ENV_GUEST_USER:-${GUEST_USER}}
GUEST_PASS=${ENV_GUEST_PASS:-${GUEST_PASS}}

# Apply CLI overrides after sourcing configuration and env
MODE=${CLI_MODE:-${MODE}}
OUT_ISO=${CLI_OUT:-${OUT_ISO}}
WORKDIR=${CLI_WORK:-${WORKDIR}}
KALI_USER=${CLI_KALI_USER:-${KALI_USER}}
KALI_PASS=${CLI_KALI_PASS:-${KALI_PASS}}
GUEST_USER=${CLI_GUEST_USER:-${GUEST_USER}}
GUEST_PASS=${CLI_GUEST_PASS:-${GUEST_PASS}}

DEFAULT_ISO="$(pwd)/kali-custom.iso"

# Apply defaults for optional fields
MODE=${MODE:-installer}
OUT_ISO=${OUT_ISO:-$DEFAULT_ISO}
WORKDIR=${WORKDIR:-/tmp/kali-auto-build}

# Automatically switch to unattended mode if all required values are supplied
if [[ $AUTO -eq 0 ]] && [[ -n "$MODE" && -n "$OUT_ISO" && -n "$WORKDIR" && -n "$KALI_USER" && -n "$KALI_PASS" && -n "$GUEST_USER" && -n "$GUEST_PASS" ]]; then
    AUTO=1
fi

if [[ $AUTO -eq 1 ]]; then
    for v in MODE OUT_ISO WORKDIR KALI_USER KALI_PASS GUEST_USER GUEST_PASS; do
        if [[ -z "${!v}" ]]; then
            echo "Error: $v must be provided for unattended execution" >&2
            exit 1
        fi
    done
else
    read -rp "Build mode (installer/live) [$MODE]: " _mode
    MODE=${_mode:-$MODE}
    read -rp "Output ISO path [$OUT_ISO]: " _out
    OUT_ISO=${_out:-$OUT_ISO}
    read -rp "Working directory [$WORKDIR]: " _wd
    WORKDIR=${_wd:-$WORKDIR}
    if [[ -z "$KALI_USER" ]]; then
        read -rp "Enter Kali username: " KALI_USER
    fi
    if [[ -z "$KALI_PASS" ]]; then
        read -srp "Enter Kali password: " KALI_PASS; echo
    fi
    if [[ -z "$GUEST_USER" ]]; then
        read -rp "Enter guest username: " GUEST_USER
    fi
    if [[ -z "$GUEST_PASS" ]]; then
        read -srp "Enter guest password: " GUEST_PASS; echo
    fi
fi

# Optionally save configuration for future unattended runs
if [[ $AUTO -eq 0 ]]; then
    read -rp "Save these settings to $CONFIG_FILE for future runs? [y/N]: " save
    if [[ "$save" =~ ^[Yy]$ ]]; then
        umask 077
        cat > "$CONFIG_FILE" <<EOF
MODE="$MODE"
OUT_ISO="$OUT_ISO"
WORKDIR="$WORKDIR"
KALI_USER="$KALI_USER"
KALI_PASS="$KALI_PASS"
GUEST_USER="$GUEST_USER"
GUEST_PASS="$GUEST_PASS"
EOF
        echo "Configuration saved to $CONFIG_FILE"
    fi
fi

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
    if [[ $KEEP_WORKDIR -eq 1 ]]; then
        PRESS_CONF="$CONFIG_FILE" KALI_USERNAME="$KALI_USER" KALI_PASSWORD="$KALI_PASS" \
        GUEST_USERNAME="$GUEST_USER" GUEST_PASSWORD="$GUEST_PASS" \
        ./build_custom_iso.sh -k "$MODE" "$OUT_ISO" "$WORKDIR"
    else
        PRESS_CONF="$CONFIG_FILE" KALI_USERNAME="$KALI_USER" KALI_PASSWORD="$KALI_PASS" \
        GUEST_USERNAME="$GUEST_USER" GUEST_PASSWORD="$GUEST_PASS" \
        ./build_custom_iso.sh "$MODE" "$OUT_ISO" "$WORKDIR"
    fi
else
    echo "build_custom_iso.sh not found" >&2
    exit 1
fi

# Record SHA256 checksum for auditing
if [[ -f "$OUT_ISO" ]]; then
    echo "SHA256 for $OUT_ISO:" 
    sha256sum "$OUT_ISO"
else
    echo "Warning: $OUT_ISO not found after build" >&2
fi
