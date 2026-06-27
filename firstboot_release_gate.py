#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate evidence composer.
# Purpose: aggregate host/VM handoff and NN IDS model-card evidence without changing state.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_FIRSTBOOT_MANIFEST = Path('/var/log/host_vm_policy_firstboot_manifest.json')
DEFAULT_MODEL_CARD = Path('/var/log/nn_ids_model_card.json')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.json')
DEFAULT_MARKDOWN = Path('/var/log/firstboot_release_gate.md')
DEFAULT_SUMMARY = Path('/var/log/firstboot_release_gate.summary.env')
FUTURE_SKEW_SECONDS = 300


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def utc_from_epoch(epoch_seconds: float) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch_seconds))


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> tuple[Dict[str, Any], Optional[str]]:
    if not path.exists() or not path.is_file():
        return {}, f'missing:{path}'
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        return {}, f'invalid_json:{path}:{exc.msg}'
    except OSError as exc:
        return {}, f'unreadable:{path}:{exc}'
    if not isinstance(payload, dict):
        return {}, f'invalid_json:{path}:top-level JSON must be an object'
    return payload, None


def timestamp_value(payload: Dict[str, Any]) -> Optional[str]:
    for key in ('created_utc', 'generated_at'):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def artifact_entry(name: str, path: Path, payload: Dict[str, Any], error: Optional[str], now_epoch: float) -> Dict[str, Any]:
    exists = path.exists() and path.is_file()
    entry: Dict[str, Any] = {
        'name': name,
        'path': str(path),
        'exists': exists,
        'sha256': sha256_file(path),
        'source_component': payload.get('component') if payload else None,
        'source_ok': payload.get('ok') if payload else None,
        'source_status': payload.get('status') or payload.get('release_gate') or payload.get('decision'),
        'source_timestamp': timestamp_value(payload),
        'read_error': error,
    }
    if exists:
        stat = path.stat()
        entry['size_bytes'] = stat.st_size
        entry['mtime_utc'] = utc_from_epoch(stat.st_mtime)
        entry['age_seconds'] = max(0, int(now_epoch - stat.st_mtime))
    return entry


def freshness_blockers(artifacts: list[Dict[str, Any]], max_artifact_age_minutes: Optional[float], now_epoch: float) -> list[str]:
    if max_artifact_age_minutes is None:
        return []
    max_age_seconds = max_artifact_age_minutes * 60
    blockers: list[str] = []
    for artifact in artifacts:
        if not artifact.get('exists'):
            continue
        name = str(artifact['name'])
        path = Path(str(artifact['path']))
        try:
            mtime_epoch = path.stat().st_mtime
        except OSError:
            blockers.append(f'{name}:mtime_unavailable')
            continue
        age_seconds = int(artifact.get('age_seconds', 0))
        if mtime_epoch > now_epoch + FUTURE_SKEW_SECONDS:
            blockers.append(f'{name}:future_mtime:{artifact.get("mtime_utc", "unknown")}')
        elif age_seconds > max_age_seconds:
            blockers.append(f'{name}:stale:{age_seconds}s>{int(max_age_seconds)}s')
    return blockers


def source_blockers(firstboot: Dict[str, Any], model_card: Dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if firstboot.get('ok') is not True:
        blockers.append('firstboot_manifest_not_ready')
    if str(firstboot.get('release_gate') or '').lower() not in {'pass', 'approved'}:
        blockers.append(f"firstboot_release_gate:{firstboot.get('release_gate', 'unknown')}")
    if model_card.get('ok') is not True:
        blockers.append('nn_ids_model_card_not_ready')
    if str(model_card.get('status') or '').lower() not in {'pass', 'approved'}:
        blockers.append(f"nn_ids_model_card_status:{model_card.get('status', 'unknown')}")
    return blockers


def build_gate(args: argparse.Namespace) -> Dict[str, Any]:
    now_epoch = time.time()
    firstboot_path = Path(args.firstboot_manifest)
    model_card_path = Path(args.model_card)
    firstboot, firstboot_error = load_json(firstboot_path)
    model_card, model_card_error = load_json(model_card_path)
    artifacts = [
        artifact_entry('host_vm_firstboot_manifest', firstboot_path, firstboot, firstboot_error, now_epoch),
        artifact_entry('nn_ids_model_card', model_card_path, model_card, model_card_error, now_epoch),
    ]
    blockers = [error for error in (firstboot_error, model_card_error) if error]
    if not blockers:
        blockers.extend(source_blockers(firstboot, model_card))
    blockers.extend(freshness_blockers(artifacts, args.max_artifact_age_minutes, now_epoch))
    blockers = sorted(set(blockers))
    ok = not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate',
        'created_utc': utc_now(),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'freshness_policy': {
            'enabled': args.max_artifact_age_minutes is not None,
            'max_artifact_age_minutes': args.max_artifact_age_minutes,
            'future_clock_skew_tolerance_seconds': FUTURE_SKEW_SECONDS,
        },
        'inputs': {
            'host_vm_firstboot': {
                'decision': firstboot.get('decision', 'unknown'),
                'release_gate': firstboot.get('release_gate', 'unknown'),
                'blocker_count': len(firstboot.get('blockers') or []),
            },
            'nn_ids_model_card': {
                'status': model_card.get('status', 'unknown'),
                'release_ready': bool(model_card.get('ok', False)),
                'blocker_count': len(model_card.get('blockers') or []),
            },
        },
        'blockers': blockers,
        'artifacts': artifacts,
        'safe_default': 'read-only gate; no host, VM, firewall, service, model, dataset, approval, restore, or firstboot state was changed',
        'privacy_note': 'records only aggregate release decisions, status fields, paths, mtimes, ages, sizes, SHA-256 digests, and blocker labels; raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, and datasets are not embedded',
        'rollback_note': 'delete generated firstboot_release_gate artifacts or revert this additive helper, packaging entry, docs, and tests; upstream firstboot manifest and NN IDS model-card artifacts are not modified',
        'operator_next_steps': operator_next_steps(blockers),
    }


def operator_next_steps(blockers: list[str]) -> list[str]:
    if not blockers:
        return [
            'Attach the JSON and Markdown gate artifacts to the release evidence bundle.',
            'Keep upstream firstboot manifest and NN IDS model-card artifacts available by SHA-256 for review.',
        ]
    actions: list[str] = []
    for blocker in blockers:
        if blocker.startswith('missing:') or blocker.startswith('invalid_json:') or blocker.startswith('unreadable:'):
            actions.append(f'Regenerate or repair the referenced evidence artifact before release: {blocker}')
        elif blocker.startswith('firstboot'):
            actions.append('Regenerate the host/VM firstboot handoff manifest after resolving policy, receipt, freshness, or packaging blockers.')
        elif blocker.startswith('nn_ids'):
            actions.append('Regenerate NN IDS schema, health, drift, receipt, and model-card evidence before model or ISO promotion.')
        elif ':stale:' in blocker or ':future_mtime:' in blocker:
            actions.append('Regenerate stale or clock-skewed release evidence before promotion.')
        else:
            actions.append(f'Review release blocker before promotion: {blocker}')
    return sorted(set(actions))


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_markdown(path: Path, gate: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    freshness = gate.get('freshness_policy') or {}
    lines = [
        '# Firstboot Release Gate',
        '',
        f"- Decision: `{gate['decision']}`",
        f"- Release gate: `{gate['release_gate']}`",
        f"- Freshness gate: `{'enabled' if freshness.get('enabled') else 'disabled'}`",
        f"- Created: `{gate['created_utc']}`",
        '',
        '## Inputs',
        '',
    ]
    inputs = gate.get('inputs') if isinstance(gate.get('inputs'), dict) else {}
    for name, payload in inputs.items():
        if not isinstance(payload, dict):
            continue
        summary = ', '.join(f'{key}=`{value}`' for key, value in sorted(payload.items()))
        lines.append(f'- `{name}`: {summary}')
    lines.extend(['', '## Blockers', ''])
    blockers = gate.get('blockers') or []
    lines.extend(f'- `{blocker}`' for blocker in blockers) if blockers else lines.append('- None.')
    lines.extend(['', '## Artifacts', ''])
    for artifact in gate.get('artifacts', []):
        digest = artifact.get('sha256') or 'n/a'
        status = 'present' if artifact.get('exists') else 'missing'
        mtime = artifact.get('mtime_utc') or 'n/a'
        age = artifact.get('age_seconds', 'n/a')
        lines.append(
            f"- `{artifact['name']}` ({status}) — `{artifact['path']}` — "
            f"mtime `{mtime}` — age `{age}`s — sha256 `{digest}`"
        )
    lines.extend([
        '',
        '## Operator next steps',
        '',
    ])
    lines.extend(f'- {step}' for step in gate.get('operator_next_steps', []))
    lines.extend([
        '',
        '## Safety, privacy, and rollback',
        '',
        f"- Safety: {gate['safe_default']}",
        f"- Privacy: {gate['privacy_note']}",
        f"- Rollback: {gate['rollback_note']}",
        '',
    ])
    path.write_text('\n'.join(lines), encoding='utf-8')


def stale_or_skewed_count(blockers: list[str]) -> int:
    return sum(1 for blocker in blockers if ':stale:' in blocker or ':future_mtime:' in blocker or ':mtime_unavailable' in blocker)


def env_quote(value: object) -> str:
    text = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    return f'"{text}"'


def summary_fields(gate: Dict[str, Any]) -> Dict[str, object]:
    blockers = gate.get('blockers') or []
    artifacts = gate.get('artifacts') or []
    return {
        'FIRSTBOOT_RELEASE_GATE_SCHEMA_VERSION': gate.get('schema_version', 1),
        'FIRSTBOOT_RELEASE_GATE_COMPONENT': gate.get('component', 'firstboot_release_gate'),
        'FIRSTBOOT_RELEASE_GATE_CREATED_UTC': gate.get('created_utc', 'unknown'),
        'FIRSTBOOT_RELEASE_GATE_OK': str(bool(gate.get('ok'))).lower(),
        'FIRSTBOOT_RELEASE_GATE_DECISION': gate.get('decision', 'unknown'),
        'FIRSTBOOT_RELEASE_GATE_STATUS': gate.get('release_gate', 'unknown'),
        'FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT': len(blockers),
        'FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT': len(artifacts),
        'FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT': stale_or_skewed_count(blockers),
        'FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE': 'aggregate_only',
    }


def write_summary(path: Path, gate: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'{key}={env_quote(value)}' for key, value in summary_fields(gate).items()]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Compose host/VM firstboot and NN IDS model-card evidence into one passive release gate.')
    parser.add_argument('--firstboot-manifest', default=str(DEFAULT_FIRSTBOOT_MANIFEST))
    parser.add_argument('--model-card', default=str(DEFAULT_MODEL_CARD))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--markdown', default=str(DEFAULT_MARKDOWN))
    parser.add_argument(
        '--summary',
        default=str(DEFAULT_SUMMARY),
        help='Write a shell-friendly aggregate status summary; pass an empty value to disable.',
    )
    parser.add_argument('--require-pass', action='store_true')
    parser.add_argument(
        '--max-artifact-age-minutes',
        type=float,
        default=None,
        help='Optional passive freshness gate; defer when evidence artifacts are older than this many minutes.',
    )
    args = parser.parse_args(argv)
    if args.max_artifact_age_minutes is not None and args.max_artifact_age_minutes <= 0:
        parser.error('--max-artifact-age-minutes must be greater than 0')
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    gate = build_gate(args)
    write_json(Path(args.output), gate)
    write_markdown(Path(args.markdown), gate)
    if args.summary:
        write_summary(Path(args.summary), gate)
    print(json.dumps({'decision': gate['decision'], 'ok': gate['ok'], 'output': args.output, 'summary': args.summary}, sort_keys=True))
    return 0 if gate['ok'] or not args.require_pass else 7


if __name__ == '__main__':
    sys.exit(main())
