# Host/VM hardening channel policy

This suite intentionally automates defensive work across the VM boundary. That is powerful, but it also means the host-to-VM and VM-to-host control path must be treated as a privileged management plane rather than a trusted home-lab shortcut.

`host_vm_channel_policy.py` validates that management-channel assumptions are explicit before host hardening scripts run. The validator is designed to be safe in CI and safe on live systems: it reads JSON policy, checks local file permissions only when requested, prints findings, and makes no remote connections or system changes.

## Threat model

The control channel can be abused if a compromised guest, compromised host, or malicious local network actor can impersonate one side, replay automation, force plaintext management, or bridge data through hypervisor conveniences. Current zero-trust guidance emphasizes explicit verification, least privilege, device/workload state, and continuous policy evaluation. Recent 2025 research on identity control planes and autonomous segmentation extends the same principle to workload identity, scoped automation credentials, and dynamic enforcement for machine-to-machine administration.

For virtualized hardening, the practical baseline is:

- No implicit trust because traffic stays on a private or host-only network.
- No password-based remote hardening automation.
- No plaintext WinRM, Telnet, exposed SMB admin paths, or broad RDP reliance.
- Pin SSH host keys or use certificate-backed trust before executing privileged scripts.
- Prefer WinRM over HTTPS only when Windows remoting is required.
- Disable shared clipboard and shared folders by default.
- Keep sessions short-lived and auditable.
- Require time synchronization so Windows, Kali, IDS, and hypervisor logs can be correlated.
- Use documented break-glass maintenance instead of leaving permissive sharing enabled.

## Policy fields

Use `host_vm_channel_policy.example.json` as the starting point.

| Field | Purpose | Defensive baseline |
| --- | --- | --- |
| `protocol` | Remote management protocol | `ssh` or `winrm-https` |
| `direction` | Intended control direction | `vm-to-host`, `host-to-vm`, or `bidirectional` |
| `hypervisor` | Hypervisor context for review | `virtualbox`, `vmware`, `hyper-v`, `kvm`, `qemu`, or `unknown` |
| `management_target` | Host-only/private address for the peer | RFC1918, link-local, or IPv6 ULA/link-local only |
| `allowed_ports` | Minimal TCP exposure for the channel | SSH `22` or WinRM HTTPS `5986`; no `23`, `445`, `3389`, or `5985` |
| `ssh_private_key` | Optional local key path for permission checks | `chmod 600` or stricter when `--check-local-files` is used |
| `pinned_known_hosts` | Optional known-hosts pin file | not world-accessible or group-writable |
| `require_host_key_pinning` | Prevent management-channel impersonation | `true` |
| `allow_password_authentication` | Password auth for automation | `false` |
| `require_transcript_logging` | Audit and rollback evidence | `true` |
| `require_time_sync` | Cross-system event correlation | `true` |
| `allow_clipboard_sharing` | Hypervisor clipboard bridge | `false` |
| `allow_shared_folders` | Hypervisor shared folder bridge | `false` |
| `max_session_minutes` | Expected control-session TTL | Prefer `30`, never above `120` |
| `break_glass.documented_procedure` | Controlled exception path | Required for review |

## Usage

Validate the example policy:

```bash
python3 host_vm_channel_policy.py --policy host_vm_channel_policy.example.json
```

Emit JSON for CI or dashboards:

```bash
python3 host_vm_channel_policy.py --policy host_vm_channel_policy.example.json --json
```

Check referenced local credential-file permissions on a live Kali VM:

```bash
python3 host_vm_channel_policy.py --policy /etc/kali-hardening/host_vm_channel_policy.json --check-local-files
```

## Entrypoint preflight enforcement

`host_hardening_windows.sh` and `host_hardening_linux.sh` now run a channel-policy preflight before SSH connectivity checks, file transfer, or remote execution. The preflight fails closed when the validator is missing, the policy file is missing, or the validator reports a failing control.

Default paths are relative to the script directory:

```bash
CHANNEL_POLICY_VALIDATOR=./host_vm_channel_policy.py
CHANNEL_POLICY_FILE=./host_vm_channel_policy.example.json
CHANNEL_POLICY_CHECK_LOCAL_FILES=1
CHANNEL_POLICY_REPORT=
```

Operators can point the entrypoints at a deployed policy without editing the scripts:

```bash
CHANNEL_POLICY_FILE=/etc/kali-hardening/host_vm_channel_policy.json ./host_hardening_linux.sh
```

Credential-file permission checks are enabled by default for live host-hardening entrypoints because remote automation should not proceed with world-accessible or group-writable key material. CI can set `CHANNEL_POLICY_CHECK_LOCAL_FILES=0` for static-only validation.

### JSON evidence artifacts

Set `CHANNEL_POLICY_REPORT` to write a machine-readable preflight result before the entrypoint attempts SSH connectivity, file transfer, or remote command execution:

```bash
CHANNEL_POLICY_CHECK_LOCAL_FILES=0 \
CHANNEL_POLICY_REPORT=artifacts/channel-policy/linux-preflight.json \
./host_hardening_linux.sh
```

The report contains the same `ok` boolean and finding list emitted by `host_vm_channel_policy.py --json`. A failing policy still stops the entrypoint before remote activity, but the JSON file is preserved so CI, dashboards, or incident-review notes can show exactly which control failed. This also creates a clean handoff point for future health-check and dashboard integrations without parsing terminal text.

### Break-glass override

A break-glass bypass exists only for console-supervised maintenance:

```bash
KALI_HARDENING_SKIP_CHANNEL_POLICY=1 ./host_hardening_windows.sh
```

Use it only when the policy file or validator is unavailable during recovery. Capture transcript logs, keep the session short, document the reason, restore the policy, and rerun validation before normal automation resumes.

## Research and guidance basis

- NIST SP 800-207 Zero Trust Architecture: explicit trust decisions and least-privilege access remain the correct design pattern for management paths.
- CISA Zero Trust Maturity Model 2.0: identity, device, network, application/workload, and data pillars map cleanly onto host/VM channel policy checks.
- 2025 identity-control-plane and identity-based segmentation research supports scoped automation credentials, workload identity, and policy-controlled machine-to-machine access.
- 2025 hypervisor exploitation research continues to show that guest/host boundaries are security boundaries that deserve least-functionality defaults, not shared-folder or clipboard convenience defaults.

## Rollback

The validator itself is additive. To roll back only the preflight enforcement, revert the changes to `host_hardening_windows.sh`, `host_hardening_linux.sh`, and `tests/test_host_vm_policy_preflight_static.sh`. To remove the full policy feature, also remove `host_vm_channel_policy.py`, `host_vm_channel_policy.example.json`, `tests/test_host_vm_channel_policy_static.sh`, and this document.
