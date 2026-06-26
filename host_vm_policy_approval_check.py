#!/usr/bin/env python3
# MINC - Review-gated host/VM policy restore approval validator for Kali hardening suite.
# Purpose: validate a human approval file before any future restore workflow may act; does not restore live state.

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STATE_DIR = Path('/var/lib/host_vm_comm_guard')
DEFAULT_PLAN = STATE_DIR / 'policy_restore_plan.json'
DEFAULT_APPROVAL = STATE_DIR / 'policy_restore_approval.json'
DEFAULT_RESULT = STATE_DIR / 'policy_restore_approval_check.json'
DEFAULT_REPORT = Path('/var/log/host_vm_policy_approval_check.report')
DEFAULT_PUBLIC_KEY = Path('/etc/host_vm_comm_guard.restore_approval.ed25519.pub')

ALLOWED_PLAN_DECISIONS = {'manual_restore_review_required'}
MAX_APPROVAL_AGE_SECONDS = 24 * 60 * 60


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def parse_utc(value: Any) -> Optional[int]:
    if not isinstance(value, str):
        return None
    try:
        return int(time.mktime(time.strptime(value, '%Y-%m-%dT%H:%M:%SZ')))
    except (TypeError, ValueError, OverflowError):
        return None


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, required: bool = True) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        if required:
            raise SystemExit(f'missing required JSON file: {path}')
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f'could not parse JSON file {path}: {exc}') from exc
    if not isinstance(data, dict):
        raise SystemExit(f'expected JSON object in {path}')
    return data


def write_json(path: Path, data: Dict[str, Any], mode: int = 0o640) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_report(path: Path, result: Dict[str, Any]) -> None:
    ensure_parent(path)
    lines = [
        f"created_utc={result.get('created_utc')}",
        f"decision={result.get('decision')}",
        f"plan_decision={result.get('plan_decision')}",
        f"approval_path={result.get('approval_path')}",
        f"changes_live_state={result.get('changes_live_state')}",
    ]
    for issue in result.get('issues', [])[:40]:
        lines.append(f"issue={issue}")
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def canonical_approval_payload(approval: Dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in approval.items() if k not in {'signature', 'signature_algorithm'}}
    return json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')


def maybe_verify_signature(approval: Dict[str, Any], public_key_path: Path) -> Tuple[bool, str]:
    """Return (ok, detail). If no public key exists, signature is explicitly optional/manual."""
    if not public_key_path.exists():
        return True, 'no public key configured; signature check skipped and manual local review is required'

    signature_b64 = approval.get('signature')
    if not isinstance(signature_b64, str) or not signature_b64.strip():
        return False, 'public key configured but approval signature is missing'
    if approval.get('signature_algorithm') != 'ed25519':
        return False, 'signature_algorithm must be ed25519 when a public key is configured'

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except Exception as exc:  # pragma: no cover - depends on optional package availability
        return False, f'cryptography package unavailable for Ed25519 verification: {exc}'

    try:
        key_bytes = public_key_path.read_bytes()
        signature = base64.b64decode(signature_b64, validate=True)
        loaded = load_pem_public_key(key_bytes)
        if not isinstance(loaded, Ed25519PublicKey):
            return False, 'configured public key is not an Ed25519 public key'
        loaded.verify(signature, canonical_approval_payload(approval))
        return True, 'ed25519 signature valid'
    except Exception as exc:
        return False, f'ed25519 signature validation failed: {exc}'


def validate_approval(plan: Dict[str, Any], approval: Dict[str, Any], approval_path: Path, public_key_path: Path, now_epoch: Optional[int] = None) -> Dict[str, Any]:
    now_epoch = int(time.time()) if now_epoch is None else now_epoch
    issues: List[str] = []
    warnings: List[str] = []

    plan_decision = str(plan.get('decision', 'missing'))
    if plan_decision not in ALLOWED_PLAN_DECISIONS:
        issues.append(f'plan decision {plan_decision!r} is not eligible for approval validation')

    if approval.get('approved') is not True:
        issues.append('approval.approved must be true')
    if approval.get('purpose') != 'host_vm_policy_restore':
        issues.append('approval.purpose must be host_vm_policy_restore')
    if approval.get('baseline_sha256') != plan.get('baseline_sha256'):
        issues.append('approval.baseline_sha256 does not match restore plan baseline_sha256')
    if approval.get('plan_created_utc') not in {plan.get('created_utc'), None}:
        issues.append('approval.plan_created_utc does not match the restore plan created_utc')
    reviewer = approval.get('reviewer')
    if not isinstance(reviewer, str) or len(reviewer.strip()) < 3 or reviewer == 'manual-review-required':
        issues.append('approval.reviewer must name the local reviewer')
    note = approval.get('note')
    if not isinstance(note, str) or len(note.strip()) < 12:
        issues.append('approval.note must document the review rationale')

    expires_epoch = parse_utc(approval.get('expires_utc'))
    if expires_epoch is None:
        issues.append('approval.expires_utc must use UTC format YYYY-MM-DDTHH:MM:SSZ')
    elif expires_epoch <= now_epoch:
        issues.append('approval has expired')
    elif expires_epoch - now_epoch > MAX_APPROVAL_AGE_SECONDS:
        issues.append('approval expiry must be within 24 hours')

    reviewed_epoch = parse_utc(approval.get('reviewed_utc'))
    if reviewed_epoch is None:
        issues.append('approval.reviewed_utc must use UTC format YYYY-MM-DDTHH:MM:SSZ')
    elif reviewed_epoch > now_epoch + 300:
        issues.append('approval.reviewed_utc cannot be in the future')
    elif now_epoch - reviewed_epoch > MAX_APPROVAL_AGE_SECONDS:
        issues.append('approval.reviewed_utc is older than 24 hours')

    sig_ok, sig_detail = maybe_verify_signature(approval, public_key_path)
    if not sig_ok:
        issues.append(sig_detail)
    else:
        warnings.append(sig_detail)

    restore_actions = [a for a in plan.get('actions', []) if isinstance(a, dict) and a.get('status') == 'manual_restore_candidate']
    if not restore_actions:
        issues.append('restore plan contains no manual_restore_candidate actions')

    decision = 'approval_valid' if not issues else 'approval_rejected'
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'mode': 'approval_check_only',
        'decision': decision,
        'plan_decision': plan_decision,
        'approval_path': str(approval_path),
        'public_key_path': str(public_key_path),
        'signature_required': public_key_path.exists(),
        'warnings': warnings,
        'issues': issues,
        'eligible_actions': restore_actions,
        'changes_live_state': False,
        'safe_default': 'validation-only; no firewall, packet-filter, service-manager, model, or host state was changed',
    }


def write_template(path: Path, plan: Dict[str, Any]) -> Dict[str, Any]:
    template = {
        'approved': False,
        'purpose': 'host_vm_policy_restore',
        'baseline_sha256': plan.get('baseline_sha256'),
        'plan_created_utc': plan.get('created_utc'),
        'reviewed_utc': utc_now(),
        'expires_utc': 'YYYY-MM-DDTHH:MM:SSZ',
        'reviewer': 'manual-review-required',
        'note': 'Set approved=true only after reviewing the restore plan, local console access, and rollback path.',
        'signature_algorithm': 'ed25519',
        'signature': '',
    }
    write_json(path, template, mode=0o600)
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'mode': 'template_only',
        'decision': 'template_written',
        'approval_path': str(path),
        'changes_live_state': False,
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate review-gated host/VM policy restore approval without restoring live state.')
    parser.add_argument('--plan', default=str(DEFAULT_PLAN), help='restore plan JSON path')
    parser.add_argument('--approval', default=str(DEFAULT_APPROVAL), help='human approval JSON path')
    parser.add_argument('--output', default=str(DEFAULT_RESULT), help='approval check result JSON path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact report path')
    parser.add_argument('--public-key', default=str(DEFAULT_PUBLIC_KEY), help='optional Ed25519 public key for signed approvals')
    parser.add_argument('--write-template', action='store_true', help='write a safe approval template with approved=false')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    plan_path = Path(args.plan)
    approval_path = Path(args.approval)
    result_path = Path(args.output)
    report_path = Path(args.report)
    public_key_path = Path(args.public_key)

    plan = load_json(plan_path, required=True)
    if args.write_template:
        result = write_template(approval_path, plan)
    else:
        approval = load_json(approval_path, required=True)
        result = validate_approval(plan, approval, approval_path, public_key_path)

    write_json(result_path, result)
    write_report(report_path, result)
    print(json.dumps({'decision': result.get('decision'), 'mode': result.get('mode'), 'output': str(result_path)}, sort_keys=True))
    return 0 if result.get('decision') in {'approval_valid', 'template_written'} else 3


if __name__ == '__main__':
    sys.exit(main())
