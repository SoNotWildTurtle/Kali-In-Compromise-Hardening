#!/bin/bash
# vm_windows_env_hardening.sh - Additional hardening for Kali VM when hosted on Windows

set -euo pipefail

HOST_IP="${HOST_IP:-192.168.1.100}"

# Restrict inbound connections to the Windows host only
ufw default deny incoming
ufw allow from "$HOST_IP" to any port 22 proto tcp comment "Allow SSH from Windows host"
ufw --force enable

# Disable VirtualBox shared clipboard and drag and drop if VirtualBox tools are installed
if command -v VBoxControl >/dev/null 2>&1; then
    VBoxControl guestproperty set /VirtualBox/GuestAdd/SharedClipboard 0 || true
    VBoxControl guestproperty set /VirtualBox/GuestAdd/DragAndDrop 0 || true
fi

