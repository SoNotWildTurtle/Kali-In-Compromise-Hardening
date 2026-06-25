# Repo-Wide Static Security Checks

`tests/run_static_security_checks.sh` is the repository-level defensive regression gate for the Kali hardening suite. It is designed to catch broken wiring before a custom ISO is built or a first-boot hardening flow is tested in a VM.

## What it validates

- Bash syntax for shell scripts under the repository and `tests/`.
- Python bytecode compilation for top-level Python modules.
- Presence of required top-level orchestrators such as `build_custom_iso.sh` and `firstboot.sh`.
- Packaging coverage for root-level `.service` and `.timer` units in `build_custom_iso.sh`.
- Missing files referenced by the ISO module arrays.
- Missing systemd units referenced by `firstboot.sh`.
- Ordering of the NN IDS model audit before the NN IDS audit gate.
- Continued packaging of recent hardening modules:
  - `host_vm_comm_guard.sh`
  - `nn_ids_model_audit.py`
  - `nn_ids_audit_gate.py`
- Baseline systemd sandboxing on high-risk service units.
- Existing module-specific static tests named `tests/test_*_static.sh`.

## Run locally

```bash
bash tests/run_static_security_checks.sh
```

The script intentionally avoids changing host state. It does not apply firewall rules, start systemd units, train models, scan networks, or modify the host/VM. It only reads repository files and performs syntax and wiring checks.

## Why this matters

The project now contains many cooperating hardening modules, systemd timers, IDS scripts, host/VM communication guards, and first-boot hooks. As the suite grows, the main risk is not a single script failing in isolation; it is a new defensive module being added but forgotten in the ISO build, referenced from first boot under the wrong name, or shipped without baseline service sandboxing.

This check turns those integration mistakes into fast failures.

## Security model

The gate supports secure-by-default development:

- Least privilege: service hardening checks require `NoNewPrivileges=true` on high-risk units.
- Isolation: service hardening checks require `PrivateTmp=true` and `ProtectSystem=` where appropriate.
- Traceability: every packaged module should map to a real repository file.
- Recoverability: the IDS audit chain is checked so audit results are generated before gate decisions.
- Safe automation: CI can run this check without touching live firewall, network, or systemd state.

## Recommended use

Run this before building a custom ISO and after adding any new `.sh`, `.py`, `.service`, or `.timer` file.

Future expansion should add a VM-based validation stage that boots the ISO in a disposable Kali VM and checks systemd timers, nftables rules, log paths, and NN IDS audit outputs live.
