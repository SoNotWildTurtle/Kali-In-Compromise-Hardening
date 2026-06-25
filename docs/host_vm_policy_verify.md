# Host/VM Policy Verification

`host_vm_policy_verify.py` is a rollback-safe verifier for the local host/VM communication posture. It compares the latest `host_vm_policy_attest.py` snapshot with a known-good baseline and writes a reviewable decision without changing firewall rules, systemd state, IDS models, or host settings.

## Why this exists

The communication guard and attestation snapshotter create a strong local evidence trail, but evidence is only useful when drift can be detected. This verifier closes that loop by turning host/VM policy drift into one of three review states:

- `accept` — current posture matches the baseline.
- `watch` — non-critical drift exists and should be reviewed.
- `restore_review` — critical drift exists, such as missing guard files, changed nftables guard state, disabled critical timers, or IDS gate degradation.

This is intentionally review-first. The script does not automatically restore a firewall policy or retrain/replace the NN IDS model. It produces JSON and a compact report that a later safe restore workflow can consume.

## Files

- Current attestation: `/var/lib/host_vm_comm_guard/policy_attestation.json`
- Known-good baseline: `/var/lib/host_vm_comm_guard/policy_attestation.baseline.json`
- Verification JSON: `/var/lib/host_vm_comm_guard/policy_verify.json`
- Compact report: `/var/log/host_vm_policy_verify.report`

## First boot behavior

After late first-boot hardening refreshes the host/VM attestation snapshot, first boot initializes the baseline if it does not already exist:

```bash
/usr/local/bin/host_vm_policy_verify.py --init-baseline
```

The timer then periodically verifies new snapshots against that baseline.

## Manual use

Verify current posture:

```bash
sudo /usr/local/bin/host_vm_policy_verify.py
```

Initialize a baseline after a trusted clean build:

```bash
sudo /usr/local/bin/host_vm_policy_verify.py --init-baseline
```

Replace a baseline intentionally after reviewed changes:

```bash
sudo /usr/local/bin/host_vm_policy_verify.py --init-baseline --force-baseline
```

Promote warnings to restore-review decisions for release validation:

```bash
sudo /usr/local/bin/host_vm_policy_verify.py --strict
```

## Compared evidence

The verifier compares:

- guard config and nftables policy file existence, hashes, and modes;
- nftables host/VM guard presence and digest;
- critical systemd service/timer active and enabled state;
- NN IDS audit gate decision drift;
- key NN IDS audit metrics such as balanced accuracy, macro F1, robustness index, and drift flags.

## Safety properties

- No network access is required.
- No firewall command is executed.
- No systemd unit is started, stopped, enabled, or disabled.
- No IDS model or dataset is modified.
- Baseline writes only happen with `--init-baseline`, and baseline replacement requires `--force-baseline`.

## Research rationale

Recent virtualization work continues to show that host/guest boundaries can fail through hypervisor, memory-isolation, and side-channel weaknesses. That makes explicit host/VM communication baselines and drift checks useful defense-in-depth. Recent IDS research also emphasizes robustness, explainability, drift, and class imbalance, so the verifier treats IDS audit-gate regression as part of host/VM posture rather than a separate afterthought.
