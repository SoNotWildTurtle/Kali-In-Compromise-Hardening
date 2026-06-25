# VM smoke check

`vm_smoke_check.sh` is a read-only post-boot validation helper for the hardened Kali VM. It is meant to be run after a custom ISO boots and `firstboot.service` has had time to complete.

## Purpose

The script closes the gap between static CI checks and a real VM boot. It confirms that the hardening suite is not only packaged, but also visible and inspectable in the installed VM.

It checks:

- expected `/usr/local/bin` hardening modules are present;
- key systemd services and timers exist and are active or enabled;
- `firstboot.service` has disabled itself after running once;
- baseline logs exist for `debsums`, Lynis, NN model audit, and audit gate;
- NN IDS audit and gate JSON artifacts parse when present;
- the host/VM communication guard status command runs;
- nftables contains expected communication-guard markers when nftables is available;
- listening sockets can be captured for review;
- recent firstboot and communication guard journal entries are copied into the smoke-check log.

## Usage

```bash
sudo /usr/local/bin/vm_smoke_check.sh
sudo /usr/local/bin/vm_smoke_check.sh --strict
sudo /usr/local/bin/vm_smoke_check.sh --log /tmp/vm-smoke.log --report /tmp/vm-smoke.report
```

Default outputs:

- detailed log: `/var/log/vm_smoke_check.log`
- compact report: `/var/log/vm_smoke_check.report`

## Safety model

The smoke check is intentionally non-mutating. It does **not** change nftables, iptables, UFW, systemd unit state, IDS models, datasets, host credentials, VM networking, or host settings. It only reads system state and records a report.

`--strict` is intended for release validation. In strict mode, warnings are promoted to failures so a packaging or firstboot regression blocks acceptance.

## Why this matters

Recent hypervisor and NIDS research keeps emphasizing that real deployment safety depends on layered validation, not just the presence of controls. The VM must prove that isolation controls, logs, scheduled audit jobs, and NN IDS guardrails are alive after boot. Static tests catch repository mistakes; this script catches boot-time and packaging mistakes.

## Recommended validation flow

1. Run `tests/run_static_security_checks.sh` before building an ISO.
2. Build the live ISO with `./build_custom_iso.sh live ./kali-hardened-live.iso`.
3. Boot it in a disposable VM snapshot.
4. Wait for firstboot activity to settle.
5. Run `sudo /usr/local/bin/vm_smoke_check.sh --strict`.
6. Review `/var/log/vm_smoke_check.report` and `/var/log/vm_smoke_check.log` before using the VM for host-hardening work.

## Failure handling

Warnings usually mean a component is missing, not enabled yet, or has not produced artifacts. Failures mean argument parsing failed, strict mode promoted warnings, or the environment did not pass required checks. Inspect the report first, then the detailed log, then the relevant service journals.
