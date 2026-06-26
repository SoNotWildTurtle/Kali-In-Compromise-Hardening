#!/usr/bin/env python3
# MINC - Read-only release wiring check for the manual host/VM restore executor.
# Defensive validation only: checks repository text files and never changes host, VM, firewall, IDS, or systemd state.

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

EXECUTOR_FILES = [
    "host_vm_policy_restore_execute.py",
    "host_vm_policy_restore_execute.service",
    "docs/host_vm_policy_restore_execute.md",
    "tests/test_host_vm_policy_restore_execute_static.sh",
]

PACKAGING_TOKENS = [
    '"host_vm_policy_restore_execute.py"',
    '"host_vm_policy_restore_execute.service"',
]

SMOKE_TOKENS = [
    "/usr/local/bin/host_vm_policy_restore_execute.py",
    "host_vm_policy_restore_execute.service",
    "/var/lib/host_vm_comm_guard/policy_restore_execute.json",
    "/var/log/host_vm_policy_restore_execute.report",
]

STATIC_TOKENS = [
    "host_vm_policy_restore_execute.py",
    "host_vm_policy_restore_execute.service",
    "test_*_static.sh",
]

DOC_TOKENS = [
    "dry-run",
    "--execute",
    "approval_valid",
    "manual_restore_review_required",
    "does not run from a timer",
]

FORBIDDEN_TIMER_NAMES = [
    "host_vm_policy_restore_execute.timer",
]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_text(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def check_file_presence(root: Path) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for relative in EXECUTOR_FILES:
        path = root / relative
        checks.append({
            "name": f"file_present:{relative}",
            "status": "pass" if path.is_file() else "fail",
            "detail": "required executor file is present" if path.is_file() else "required executor file is missing",
        })
    return checks


def check_tokens(label: str, text: str, tokens: List[str]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for token in tokens:
        present = token in text
        checks.append({
            "name": f"{label}:{token}",
            "status": "pass" if present else "fail",
            "detail": "token present" if present else "token missing",
        })
    return checks


def check_no_timer(root: Path, build_text: str, firstboot_text: str) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for timer_name in FORBIDDEN_TIMER_NAMES:
        exists = (root / timer_name).exists()
        referenced = timer_name in build_text or timer_name in firstboot_text
        checks.append({
            "name": f"no_timer_file:{timer_name}",
            "status": "pass" if not exists else "fail",
            "detail": "manual restore executor remains non-recurring" if not exists else "forbidden timer file exists",
        })
        checks.append({
            "name": f"no_timer_reference:{timer_name}",
            "status": "pass" if not referenced else "fail",
            "detail": "manual restore executor timer is not referenced" if not referenced else "forbidden timer is referenced",
        })
    return checks


def check_service_sandbox(service_text: str) -> List[Dict[str, Any]]:
    required = [
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "RestrictAddressFamilies=AF_UNIX",
        "MemoryDenyWriteExecute=true",
        "ConditionPathExists=/var/lib/host_vm_comm_guard/policy_restore_approval_check.json",
    ]
    return check_tokens("service_sandbox", service_text, required)


def evaluate(root: Path) -> Dict[str, Any]:
    build_text = read_text(root, "build_custom_iso.sh")
    firstboot_text = read_text(root, "firstboot.sh")
    smoke_text = read_text(root, "vm_smoke_check.sh")
    static_text = read_text(root, "tests/run_static_security_checks.sh")
    service_text = read_text(root, "host_vm_policy_restore_execute.service")
    doc_text = read_text(root, "docs/host_vm_policy_restore_execute.md")

    checks: List[Dict[str, Any]] = []
    checks.extend(check_file_presence(root))
    checks.extend(check_tokens("iso_packaging", build_text, PACKAGING_TOKENS))
    checks.extend(check_tokens("vm_smoke", smoke_text, SMOKE_TOKENS))
    checks.extend(check_tokens("repo_static", static_text, STATIC_TOKENS))
    checks.extend(check_tokens("documentation", doc_text, DOC_TOKENS))
    checks.extend(check_service_sandbox(service_text))
    checks.extend(check_no_timer(root, build_text, firstboot_text))

    failed = [item for item in checks if item["status"] != "pass"]
    decision = "release_ready" if not failed else "wiring_review_required"
    return {
        "schema_version": 1,
        "created_utc": utc_now(),
        "decision": decision,
        "changes_live_state": False,
        "checks_passed": len(checks) - len(failed),
        "checks_failed": len(failed),
        "checks": checks,
        "safe_default": "read-only repository text inspection; manual restore executor must not be timer-driven",
    }


def write_outputs(result: Dict[str, Any], output: Optional[Path], report: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"created_utc={result['created_utc']}",
            f"decision={result['decision']}",
            f"changes_live_state={result['changes_live_state']}",
            f"checks_passed={result['checks_passed']}",
            f"checks_failed={result['checks_failed']}",
        ]
        for item in result["checks"]:
            if item["status"] != "pass":
                lines.append(f"issue={item['name']}|{item['detail']}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check manual restore executor release wiring without mutating live state.")
    parser.add_argument("--root", default=".", help="repository root to inspect")
    parser.add_argument("--output", help="optional JSON output path")
    parser.add_argument("--report", help="optional compact report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero when wiring review is required")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    result = evaluate(Path(args.root).resolve())
    write_outputs(result, Path(args.output) if args.output else None, Path(args.report) if args.report else None)
    print(json.dumps({
        "decision": result["decision"],
        "checks_passed": result["checks_passed"],
        "checks_failed": result["checks_failed"],
    }, sort_keys=True))
    if args.strict and result["decision"] != "release_ready":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
