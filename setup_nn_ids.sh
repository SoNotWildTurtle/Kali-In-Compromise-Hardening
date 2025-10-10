#!/bin/bash
# setup_nn_ids.sh - install dependencies and train neural network IDS
set -euo pipefail

LOG_DIR="/var/log/nnids"
LOG_FILE="$LOG_DIR/setup_nn_ids.log"
SETUP_FLAG="/opt/nnids/.setup_complete"

mkdir -p "$LOG_DIR" /opt/nnids/datasets

log_step() {
    local message="$1"
    shift
    local started
    started=$(date +%s)
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $message" | tee -a "$LOG_FILE"
    if "$@" >>"$LOG_FILE" 2>&1; then
        local finished
        finished=$(date +%s)
        local duration=$((finished - started))
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] SUCCESS: $message (${duration}s)" | tee -a "$LOG_FILE"
    else
        local rc=$?
        local finished
        finished=$(date +%s)
        local duration=$((finished - started))
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] FAILURE: $message after ${duration}s (exit $rc)" | tee -a "$LOG_FILE"
        return $rc
    fi
}

echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] ==== Neural IDS setup starting ==== " | tee -a "$LOG_FILE"

for required in python3 pip3; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Missing required command: $required" | tee -a "$LOG_FILE"
        exit 1
    fi
done

log_step "Installing Python dependencies" pip3 install --no-input pandas scikit-learn joblib scapy
log_step "Preparing datasets directory" mkdir -p /opt/nnids/datasets
log_step "Running baseline IDS training" python3 /usr/local/bin/nn_ids_setup.py
log_step "Training GA Tech syscall model" python3 /usr/local/bin/nn_syscall_gt.py --train
log_step "Training OS baseline model" python3 /usr/local/bin/nn_os_train.py
log_step "Training GA Tech process model" python3 /usr/local/bin/nn_process_gt.py --train

touch "$SETUP_FLAG"
echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Setup complete - flag created at $SETUP_FLAG" | tee -a "$LOG_FILE"
