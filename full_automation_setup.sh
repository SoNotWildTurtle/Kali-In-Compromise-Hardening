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

# Verify that every module referenced in the README exists
bash ./verify_readme_modules.sh

# Capture an environment snapshot for auditing and troubleshooting if the helper exists.
if [[ -x ./press_environment_report.sh ]]; then
    env_report="$(mktemp "${TMPDIR:-/tmp}/press_environment_XXXXXX.md")"
    ./press_environment_report.sh -o "$env_report"
    echo "Environment report saved to $env_report"
fi

# Some broken environments lose the dpkg-split helper which causes
# "unable to execute split package reassembly" errors during apt
# operations. Re-installing dpkg restores the missing binary.
ensure_dpkg_split() {
    if ! command -v dpkg-split >/dev/null 2>&1; then
        echo "dpkg-split missing, reinstalling dpkg..."
        apt-get update
        apt-get install -y --reinstall dpkg
    fi
}

check_network() {
    local url="https://kali.org/"
    for _ in {1..5}; do
        if curl -fs --head "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "Unable to reach $url; network connectivity is required." >&2
    exit 1
}

require_space() {
    local path=$1
    local need_mb=${2:-8192}
    mkdir -p "$path"
    local avail
    avail=$(df -Pm "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -z "$avail" ]]; then
        echo "Unable to determine free space for $path" >&2
        exit 1
    fi
    if (( avail < need_mb )); then
        echo "Insufficient space on $path: need ${need_mb}MB, have ${avail}MB" >&2
        exit 1
    fi
}

# Verify sufficient available memory (in MB)
require_memory() {
    local need_mb=${1:-2048}
    local avail
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    if (( avail < need_mb )); then
        echo "Low available memory: need ${need_mb}MB, have ${avail}MB — throttling" >&2
        command -v renice >/dev/null && renice +10 $$ >/dev/null 2>&1 || true
        command -v ionice >/dev/null && ionice -c3 -p $$ >/dev/null 2>&1 || true
    fi
}

ensure_dependencies() {
    local missing=()
    for cmd in curl gpg bsdtar mkisofs isohybrid dialog nmap netdiscover arp-scan nbtscan dnsrecon whatweb enum4linux nikto sslscan snmpwalk masscan traceroute git pre-commit shellcheck flake8 bandit black codespell gitleaks isort python3 pip3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            case "$cmd" in
                curl)        missing+=(curl) ;;
                gpg)         missing+=(gnupg) ;;
                bsdtar)      missing+=(libarchive-tools) ;;
                mkisofs)     missing+=(genisoimage) ;;
                isohybrid)   missing+=(syslinux-utils) ;;
                dialog)      missing+=(dialog) ;;
                nmap)        missing+=(nmap) ;;
                netdiscover) missing+=(netdiscover) ;;
                arp-scan)    missing+=(arp-scan) ;;
                nbtscan)     missing+=(nbtscan) ;;
                dnsrecon)    missing+=(dnsrecon) ;;
                whatweb)     missing+=(whatweb) ;;
                enum4linux)  missing+=(enum4linux) ;;
                nikto)       missing+=(nikto) ;;
                sslscan)     missing+=(sslscan) ;;
                snmpwalk)    missing+=(snmp) ;;
                masscan)     missing+=(masscan) ;;
                traceroute)  missing+=(traceroute) ;;
                git)         missing+=(git) ;;
                pre-commit)  missing+=(pre-commit) ;;
                shellcheck)  missing+=(shellcheck) ;;
                flake8)      missing+=(flake8) ;;
                bandit)      missing+=(bandit) ;;
                black)       missing+=(black) ;;
                codespell)   missing+=(codespell) ;;
                gitleaks)    missing+=(gitleaks) ;;
                isort)       missing+=(python3-isort) ;;
                python3)     missing+=(python3) ;;
                pip3)        missing+=(python3-pip) ;;
            esac
        fi
    done
    if (( ${#missing[@]} )); then
        apt-get update
        apt-get install -y "${missing[@]}"
    fi
}

usage() {
    echo "Usage: $0 [-c config] [-m installer|live] [-o output_iso] [-w workdir] [-u kali_user] [-p kali_pass] [-g guest_user] [-s guest_pass] [-k] [-a] [-S]" >&2
    echo "       -a : run non-interactively; all options must be provided via config or CLI" >&2
    echo "       -S : save supplied options to the config file without prompting" >&2
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
SAVE_CONFIG=0

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

while getopts "c:m:o:w:u:p:g:s:kaSh" opt; do
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
        S) SAVE_CONFIG=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND-1))

ensure_dpkg_split
ensure_dependencies
check_network
require_memory 2048

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
if [[ $SAVE_CONFIG -eq 1 ]]; then
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
elif [[ $AUTO -eq 0 ]]; then
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

# Ensure sufficient disk space before heavy operations
require_space "$(dirname "$OUT_ISO")" 8192
require_space "$WORKDIR" 8192

# Remove old ISO and checksums to avoid reporting success with stale files
rm -f "$OUT_ISO" "${OUT_ISO}.sha256" "${OUT_ISO}.sha256.asc"

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

# Record SHA256 checksum for auditing and save alongside the ISO
if [[ -s "$OUT_ISO" ]]; then
    echo "SHA256 for $OUT_ISO:"
    sha256sum "$OUT_ISO" | tee "${OUT_ISO}.sha256"
    echo "Checksum written to ${OUT_ISO}.sha256"
    sha256sum -c "${OUT_ISO}.sha256"
    if command -v gpg >/dev/null 2>&1 && gpg --list-secret-keys >/dev/null 2>&1; then
        gpg --armor --detach-sign "${OUT_ISO}.sha256"
        echo "Checksum signature written to ${OUT_ISO}.sha256.asc"
    fi
else
    echo "Error: $OUT_ISO not found after build" >&2
    exit 1
fi
