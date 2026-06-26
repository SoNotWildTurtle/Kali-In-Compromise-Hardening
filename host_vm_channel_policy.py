#!/usr/bin/env python3
"""Validate host<->VM management-channel policy before hardening.

The hardening suite intentionally crosses the host/guest boundary for defensive
administration. That boundary should be treated as a high-risk security control,
not as a trusted local network. This validator provides a small policy-as-code
contract that can be used by Bash, PowerShell, CI, and documentation to agree on
minimum channel requirements before remote hardening steps execute.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

DEFAULT_POLICY_PATHS = (
    Path("./host_vm_channel_policy.json"),
    Path("/etc/kali-hardening/host_vm_channel_policy.json"),
)

APPROVED_PROTOCOLS = {"ssh", "winrm-https"}
APPROVED_HYPERVISORS = {"virtualbox", "vmware", "hyper-v", "kvm", "qemu", "unknown"}
APPROVED_DIRECTIONS = {"vm-to-host", "host-to-vm", "bidirectional"}
PRIVATE_MANAGEMENT_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fd00::/8",
        "fe80::/10",
    )
)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}


class PolicyError(ValueError):
    """Raised when the JSON policy cannot be parsed as a mapping."""


def _finding(severity: str, code: str, message: str) -> Finding:
    return Finding(severity=severity, code=code, message=message)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_private_management_target(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in PRIVATE_MANAGEMENT_NETS)


def _file_mode_findings(path: str, field_name: str) -> list[Finding]:
    if not path:
        return []
    expanded = Path(os.path.expanduser(path))
    if not expanded.exists():
        return [
            _finding(
                "warn",
                f"{field_name}.missing",
                f"{field_name} points to {expanded}, but the file does not exist on this system.",
            )
        ]
    mode = stat.S_IMODE(expanded.stat().st_mode)
    findings: list[Finding] = []
    if mode & stat.S_IRWXO:
        findings.append(
            _finding(
                "fail",
                f"{field_name}.world_accessible",
                f"{field_name} {expanded} is accessible by other users; use chmod 600 or stricter.",
            )
        )
    if mode & stat.S_IWGRP:
        findings.append(
            _finding(
                "fail",
                f"{field_name}.group_writable",
                f"{field_name} {expanded} is group-writable; use chmod 600 or stricter.",
            )
        )
    return findings


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load a policy JSON document from a specific path or standard locations."""
    candidate_paths: Iterable[Path]
    if path is not None:
        candidate_paths = (path,)
    else:
        candidate_paths = DEFAULT_POLICY_PATHS

    for candidate in candidate_paths:
        if candidate.exists():
            with candidate.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise PolicyError("host VM channel policy must be a JSON object")
            return data
    raise FileNotFoundError(
        "No host VM channel policy found. Checked: "
        + ", ".join(str(candidate) for candidate in candidate_paths)
    )


def validate_policy(policy: dict[str, Any], check_local_files: bool = False) -> list[Finding]:
    """Return policy findings without mutating the host or VM."""
    findings: list[Finding] = []

    protocol = str(policy.get("protocol", "")).lower().strip()
    if protocol not in APPROVED_PROTOCOLS:
        findings.append(
            _finding(
                "fail",
                "protocol.unsupported",
                f"protocol must be one of {sorted(APPROVED_PROTOCOLS)}, got {protocol or '<missing>'}.",
            )
        )

    direction = str(policy.get("direction", "")).lower().strip()
    if direction not in APPROVED_DIRECTIONS:
        findings.append(
            _finding(
                "fail",
                "direction.unsupported",
                f"direction must be one of {sorted(APPROVED_DIRECTIONS)}, got {direction or '<missing>'}.",
            )
        )

    hypervisor = str(policy.get("hypervisor", "unknown")).lower().strip()
    if hypervisor not in APPROVED_HYPERVISORS:
        findings.append(
            _finding(
                "warn",
                "hypervisor.unknown",
                f"hypervisor {hypervisor!r} is not in the reviewed list {sorted(APPROVED_HYPERVISORS)}.",
            )
        )

    target = str(policy.get("management_target", "")).strip()
    if not target:
        findings.append(_finding("fail", "target.missing", "management_target is required."))
    elif not _is_private_management_target(target):
        findings.append(
            _finding(
                "fail",
                "target.not_private",
                "management_target must be a private, link-local, or ULA address; never expose hardening control channels publicly.",
            )
        )

    allowed_ports = {int(port) for port in _as_list(policy.get("allowed_ports")) if str(port).isdigit()}
    if protocol == "ssh" and allowed_ports and 22 not in allowed_ports:
        findings.append(_finding("fail", "ssh.port_missing", "SSH policies must include TCP/22 in allowed_ports."))
    if protocol == "winrm-https" and allowed_ports and 5986 not in allowed_ports:
        findings.append(_finding("fail", "winrm_https.port_missing", "WinRM HTTPS policies must include TCP/5986 in allowed_ports."))
    if any(port in allowed_ports for port in (23, 445, 3389, 5985)):
        findings.append(
            _finding(
                "fail",
                "ports.insecure_management",
                "Disallow Telnet, SMB admin exposure, RDP, and plaintext WinRM on the VM/host hardening channel.",
            )
        )

    if bool(policy.get("allow_password_authentication", False)):
        findings.append(
            _finding(
                "fail",
                "auth.password_enabled",
                "Password authentication is not approved for automated host/VM hardening; use keys or certificates.",
            )
        )

    if not bool(policy.get("require_host_key_pinning", True)):
        findings.append(
            _finding(
                "fail",
                "ssh.host_key_pinning_disabled",
                "Host key or certificate pinning must remain enabled to prevent management-channel impersonation.",
            )
        )

    if not bool(policy.get("require_transcript_logging", True)):
        findings.append(
            _finding(
                "warn",
                "logging.transcript_disabled",
                "Transcript/session logging should remain enabled for rollback, incident review, and auditability.",
            )
        )

    if not bool(policy.get("require_time_sync", True)):
        findings.append(
            _finding(
                "warn",
                "time_sync.disabled",
                "Time synchronization should be required so host and VM logs can be correlated.",
            )
        )

    if bool(policy.get("allow_clipboard_sharing", False)):
        findings.append(
            _finding(
                "fail",
                "hypervisor.clipboard_sharing",
                "Shared clipboard should be disabled across the host/VM boundary except during explicit break-glass maintenance.",
            )
        )

    if bool(policy.get("allow_shared_folders", False)):
        findings.append(
            _finding(
                "fail",
                "hypervisor.shared_folders",
                "Shared folders should be disabled by default; move artifacts through authenticated, logged channels.",
            )
        )

    max_session_minutes = int(policy.get("max_session_minutes", 30))
    if max_session_minutes <= 0 or max_session_minutes > 120:
        findings.append(
            _finding(
                "warn",
                "session.ttl_too_long",
                "Management sessions should be short-lived; use 120 minutes or less and prefer 30 minutes or less.",
            )
        )

    break_glass = policy.get("break_glass", {})
    if not isinstance(break_glass, dict) or not break_glass.get("documented_procedure"):
        findings.append(
            _finding(
                "warn",
                "break_glass.undocumented",
                "Document a break-glass procedure before enabling bidirectional hardening automation.",
            )
        )

    if check_local_files:
        findings.extend(_file_mode_findings(str(policy.get("ssh_private_key", "")), "ssh_private_key"))
        findings.extend(_file_mode_findings(str(policy.get("pinned_known_hosts", "")), "pinned_known_hosts"))
        findings.extend(_file_mode_findings(str(policy.get("client_certificate", "")), "client_certificate"))

    return findings


def render_findings(findings: list[Finding], json_output: bool = False) -> str:
    if json_output:
        return json.dumps({"ok": not any(f.severity == "fail" for f in findings), "findings": [f.as_dict() for f in findings]}, indent=2)
    if not findings:
        return "PASS: host/VM channel policy meets the current defensive baseline."
    return "\n".join(f"{finding.severity.upper()}: {finding.code}: {finding.message}" for finding in findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Kali host<->VM hardening channel policy.")
    parser.add_argument("--policy", type=Path, help="Path to host_vm_channel_policy.json")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--check-local-files", action="store_true", help="Verify referenced local credential files exist and are not over-permissive")
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy)
        findings = validate_policy(policy, check_local_files=args.check_local_files)
    except Exception as exc:  # noqa: BLE001 - CLI must report parse/load errors cleanly.
        findings = [_finding("fail", "policy.load_error", str(exc))]

    print(render_findings(findings, json_output=args.json))
    return 1 if any(finding.severity == "fail" for finding in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
