#!/bin/bash
# vm_linux_env_hardening.sh - Additional hardening for Kali VM when hosted on Linux
set -euo pipefail

HOST_IP="${HOST_IP:-192.168.1.200}"

# Restrict inbound SSH to the host only
ufw default deny incoming
ufw allow from "$HOST_IP" to any port 22 proto tcp comment "Allow SSH from Linux host"
ufw --force enable

# Disable clipboard sharing if VirtualBox or VMware tools are present
if command -v VBoxControl >/dev/null 2>&1; then
    VBoxControl guestproperty set /VirtualBox/GuestAdd/SharedClipboard 0 || true
    VBoxControl guestproperty set /VirtualBox/GuestAdd/DragAndDrop 0 || true
fi

if command -v vmtoolsd >/dev/null 2>&1; then
    vmware-toolbox-cmd config set clipboard.disable 1 || true
fi
