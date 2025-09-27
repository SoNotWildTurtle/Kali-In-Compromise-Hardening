#!/bin/bash
# anti_wipe_monitor.sh - watch critical directories for deletion attempts
# Logs suspicious activity and re-applies immutable flags.

set -euo pipefail

LOG_FILE="/var/log/anti_wipe.log"
WATCH_DIRS=(/etc /bin /sbin /usr/bin /opt/nnids)

# Ensure log file exists
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

inotifywait -m -e delete,delete_self,move,move_self "${WATCH_DIRS[@]}" 2>/dev/null |
while read -r path action file; do
    msg="$(date) - Potential wipe activity: $action on ${path}${file}"
    echo "$msg" >> "$LOG_FILE"
    logger -t anti_wipe_monitor "$msg"
    chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/critical_backup/* 2>/dev/null || true
    if [[ "$path" == *"/opt/nnids"* ]]; then
        if [ -f /usr/local/bin/nn_ids_restore.py ]; then
            python3 /usr/local/bin/nn_ids_restore.py >> "$LOG_FILE" 2>&1 || true
        fi
    fi
done
