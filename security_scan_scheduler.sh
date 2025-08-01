#!/bin/bash
# security_scan_scheduler.sh - schedule recurring security scans
set -euo pipefail

cat <<'CRON' > /etc/cron.d/security-scans
0 2 * * * root /usr/bin/lynis audit system --quick >> /var/log/lynis_cron.log 2>&1
30 2 * * * root /usr/bin/rkhunter --update && /usr/bin/rkhunter --cronjob --report-warnings-only >> /var/log/rkhunter_cron.log 2>&1
CRON

chmod 600 /etc/cron.d/security-scans

