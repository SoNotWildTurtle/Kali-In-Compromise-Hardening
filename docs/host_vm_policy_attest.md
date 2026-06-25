# Host/VM Policy Attestation

`host_vm_policy_attest.py` creates a local JSON evidence snapshot for the hardened Kali guest. It is designed to make host-to-VM and VM-to-host security posture reviewable without changing firewall, IDS, or host state.

## What it records

The snapshot includes:

- Host identity metadata: hostname, platform, kernel, and architecture.
- Hashes and metadata for `/etc/host_vm_comm_guard.conf` and `/etc/nftables.d/host_vm_comm_guard.nft`.
- Read-only nftables status for the `host_vm_comm_guard` table.
- systemd state for the communication guard and NN IDS audit chain.
- Summaries and file hashes for the NN IDS model audit and audit gate JSON artifacts.
- A canonical `snapshot_sha256` so later checks can detect unexpected policy drift.

The default output paths are:

- `/var/lib/host_vm_comm_guard/policy_attestation.json`
- `/var/log/host_vm_policy_attest.report`
- `/var/lib/host_vm_comm_guard/policy_attestation.sig` when local signing is configured

## Optional local signing

The script signs snapshots only when a local private key exists at `/etc/host_vm_comm_guard/attestation_ed25519.key`. If the key is missing, the snapshot is still hash-attested and reports `signed=false`.

Example key generation for a lab VM:

```bash
sudo install -d -m 0750 /etc/host_vm_comm_guard
sudo openssl genpkey -algorithm ED25519 -out /etc/host_vm_comm_guard/attestation_ed25519.key
sudo chmod 0600 /etc/host_vm_comm_guard/attestation_ed25519.key
sudo openssl pkey -in /etc/host_vm_comm_guard/attestation_ed25519.key -pubout \
  -out /etc/host_vm_comm_guard/attestation_ed25519.pub
```

Keep the private key local to the hardened VM or replace it with a lab CA/HSM workflow. Do not copy it into logs, tickets, chat, or host automation.

## Systemd integration

`host_vm_policy_attest.service` is a sandboxed one-shot service. The timer refreshes the evidence snapshot shortly after boot and then hourly with randomized delay.

The service is intentionally read-only except for:

- `/var/lib/host_vm_comm_guard`
- `/var/log`
- `/etc/host_vm_comm_guard`

## Threat model value

This module does not prove that the host or hypervisor is uncompromised. It gives defenders a compact evidence object for reviewing whether the expected communication guard, nftables policy, and NN IDS audit chain are still present after boot.

That matters because recent virtualization research continues to emphasize host/guest isolation risk and cross-domain attack surfaces. Recent NIDS research also emphasizes drift, explainability, and adversarial robustness as deployment risks, so the attestation includes model audit and audit-gate summaries rather than only firewall state.

## Validation

Run the static validation suite from the repository root:

```bash
bash tests/run_static_security_checks.sh
```

Run the module-specific static test:

```bash
bash tests/test_host_vm_policy_attest_static.sh
```

Run a local non-signing snapshot test without touching privileged paths:

```bash
python3 host_vm_policy_attest.py \
  --output /tmp/policy_attestation.json \
  --report /tmp/policy_attestation.report \
  --signature /tmp/policy_attestation.sig \
  --no-sign
```
