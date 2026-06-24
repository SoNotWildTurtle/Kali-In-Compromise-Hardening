# Host VM Communication Guard

`host_vm_comm_guard.sh` adds a reversible nftables policy for the Kali guest side of host-to-VM and VM-to-host management traffic. The goal is to make trusted host management explicit instead of leaving SSH, WinRM-over-TLS, or WireGuard reachable from every network attached to the VM.

## Threat model

This module assumes a defensive lab or recovery VM where the Kali guest may need to harden or inspect a host, but the VM should not expose management ports broadly. It addresses:

- accidental exposure of SSH or WinRM listener ports to bridged or shared networks;
- unsafe lateral management paths between a compromised host and the VM;
- lack of audit logs for rejected host-management traffic;
- policy drift when a VM moves between NAT, host-only, and bridged networks.

It does **not** attempt stealth, persistence, credential capture, evasion, or unauthorized access.

## Defaults

The script creates `/etc/host_vm_comm_guard.conf` if missing:

```bash
HOST_VM_HOST_CIDR="192.168.56.1/32"
HOST_VM_ALLOWED_TCP="22,5986"
HOST_VM_ALLOWED_UDP="51820"
HOST_VM_PERMISSIVE_OUTBOUND="1"
```

Recommended host CIDRs:

- VirtualBox host-only: usually `192.168.56.1/32`.
- VMware vmnet host adapter: often a `172.16.x.1/32` or `192.168.x.1/32` address.
- Hyper-V default switch: use the exact host-side gateway IP where possible.
- Dedicated lab subnet: use the narrowest subnet that contains only the host/guest management link.

## Commands

```bash
sudo ./host_vm_comm_guard.sh check
sudo ./host_vm_comm_guard.sh apply
sudo ./host_vm_comm_guard.sh status
sudo ./host_vm_comm_guard.sh remove
```

`check` validates the config and generated nftables syntax before loading rules. `remove` deletes only the `inet host_vm_comm_guard` table and generated policy file.

## Design notes

- Uses nftables rather than iptables for current Debian/Kali compatibility.
- Installs an include under `/etc/nftables.d/*.nft` so this module is auditable and separable from other firewall rules.
- Keeps outbound permissive by default to avoid breaking updates or package retrieval during first boot.
- Supports strict egress mode with `HOST_VM_PERMISSIVE_OUTBOUND="0"` once DNS, DHCP, NTP, web updates, and host-management channels are confirmed.
- Logs denied management-port traffic with clear prefixes for later IDS ingestion.

## IDS integration path

The denied prefixes `host-vm-deny-in-tcp`, `host-vm-deny-in-udp`, and `host-vm-deny-out` are intentionally stable. Future IDS work should parse these prefixes as high-signal policy violations and add features such as:

- source/destination tuple frequency;
- management-port deny rate per minute;
- first-seen host-side source address;
- drift from approved host CIDR;
- disagreement between nftables denies and NN IDS confidence.

## Research alignment

Recent IDS research emphasizes concept drift, imbalanced traffic, adversarial robustness, and operational explainability. This guard creates deterministic, labeled policy events that can help the NN IDS distinguish expected host-management channels from suspicious host/guest traffic drift without relying only on opaque packet features.
