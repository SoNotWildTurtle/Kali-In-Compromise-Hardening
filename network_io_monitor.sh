#!/bin/bash
# network_io_monitor.sh - set up iptables logging for inbound/outbound traffic
set -euo pipefail

# IPv4 chains
iptables -nL INLOG >/dev/null 2>&1 || iptables -N INLOG
iptables -nL OUTLOG >/dev/null 2>&1 || iptables -N OUTLOG
if ! iptables -C INPUT -j INLOG >/dev/null 2>&1; then
    iptables -A INPUT -j INLOG
fi
if ! iptables -C OUTPUT -j OUTLOG >/dev/null 2>&1; then
    iptables -A OUTPUT -j OUTLOG
fi
iptables -F INLOG
iptables -A INLOG -m limit --limit 5/min -j LOG --log-prefix "INBOUND: " --log-level 4
iptables -A INLOG -j RETURN
iptables -F OUTLOG
iptables -A OUTLOG -m limit --limit 5/min -j LOG --log-prefix "OUTBOUND: " --log-level 4
iptables -A OUTLOG -j RETURN

# IPv6 chains
ip6tables -nL INLOG >/dev/null 2>&1 || ip6tables -N INLOG
ip6tables -nL OUTLOG >/dev/null 2>&1 || ip6tables -N OUTLOG
if ! ip6tables -C INPUT -j INLOG >/dev/null 2>&1; then
    ip6tables -A INPUT -j INLOG
fi
if ! ip6tables -C OUTPUT -j OUTLOG >/dev/null 2>&1; then
    ip6tables -A OUTPUT -j OUTLOG
fi
ip6tables -F INLOG
ip6tables -A INLOG -m limit --limit 5/min -j LOG --log-prefix "INBOUND6: " --log-level 4
ip6tables -A INLOG -j RETURN
ip6tables -F OUTLOG
ip6tables -A OUTLOG -m limit --limit 5/min -j LOG --log-prefix "OUTBOUND6: " --log-level 4
ip6tables -A OUTLOG -j RETURN

# rsyslog rules
RSYSLOG_RULES=/etc/rsyslog.d/20-iptables.conf
if ! grep -q INBOUND "$RSYSLOG_RULES" 2>/dev/null; then
cat <<'RSYS' > "$RSYSLOG_RULES"
:msg, contains, "INBOUND: " /var/log/inbound.log
:msg, contains, "OUTBOUND: " /var/log/outbound.log
:msg, contains, "INBOUND6: " /var/log/inbound6.log
:msg, contains, "OUTBOUND6: " /var/log/outbound6.log
& stop
RSYS
    systemctl restart rsyslog
fi

LOGROTATE_CONF=/etc/logrotate.d/network_io
if [ ! -f "$LOGROTATE_CONF" ]; then
cat <<'ROT' > "$LOGROTATE_CONF"
/var/log/inbound.log /var/log/outbound.log /var/log/inbound6.log /var/log/outbound6.log {
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
}
ROT
fi

echo "Network I/O monitoring enabled"
