#!/usr/bin/env python3
"""Run a focused set of health checks for the neural network IDS stack."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Tuple

MODEL = Path("/opt/nnids/ids_model.pkl")
ALERT_STATS = Path("/var/lib/nn_ids/alert_stats.json")
LOG = Path("/var/log/nn_ids_health.log")

CRITICAL_SERVICES: Sequence[Tuple[str, str]] = (
    ("nn_ids.service", "Neural IDS inference service"),
    ("process_monitor.service", "Process monitor"),
    ("nn_syscall_monitor.service", "Syscall monitor"),
)

CRITICAL_TIMERS: Sequence[Tuple[str, str]] = (
    ("nn_ids_capture.timer", "Packet capture scheduler"),
    ("nn_ids_retrain.timer", "Model retraining scheduler"),
    ("nn_ids_snapshot.timer", "Snapshot scheduler"),
    ("nn_ids_restore.timer", "Self-heal scheduler"),
)

SYSTEMCTL_AVAILABLE = shutil.which("systemctl") is not None
_SYSTEMCTL_WARNING_EMITTED = False


def create_logger(verbose: bool) -> Callable[[str], None]:
    """Return a logger callable that records to disk and optionally stdout."""

    LOG.parent.mkdir(parents=True, exist_ok=True)

    def _log(message: str) -> None:
        timestamp = datetime.utcnow().isoformat(timespec="seconds")
        line = f"{timestamp} {message}"
        with LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")
        if verbose:
            print(line)

    return _log


def _systemctl_available(logger: Callable[[str], None]) -> bool:
    """Log a warning once when systemctl is unavailable."""

    global _SYSTEMCTL_WARNING_EMITTED
    if SYSTEMCTL_AVAILABLE:
        return True
    if not _SYSTEMCTL_WARNING_EMITTED:
        logger("systemctl not available; skipping unit checks")
        _SYSTEMCTL_WARNING_EMITTED = True
    return False


def service_active(name: str) -> bool:
    if not SYSTEMCTL_AVAILABLE:
        return False
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def restart_service(name: str) -> Tuple[bool, Optional[str]]:
    if not SYSTEMCTL_AVAILABLE:
        return False, "systemctl not available"
    result = subprocess.run(
        ["systemctl", "restart", name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return True, None
    detail = (result.stderr or result.stdout or "unknown error").strip()
    return False, detail


def check_services(
    logger: Callable[[str], None], restart: bool = True
) -> bool:
    """Check that critical services are active, restarting when requested."""

    if not _systemctl_available(logger):
        return True

    healthy = True
    for unit, description in CRITICAL_SERVICES:
        if service_active(unit):
            logger(f"{description} ({unit}) active")
            continue
        healthy = False
        logger(f"{description} ({unit}) inactive")
        if not restart:
            continue
        ok, detail = restart_service(unit)
        if ok:
            logger(f"Restarted {unit} successfully")
        else:
            logger(f"Failed to restart {unit}: {detail}")
    return healthy


def check_timers(logger: Callable[[str], None]) -> bool:
    """Ensure timer units are active so scheduled jobs continue to run."""

    if not _systemctl_available(logger):
        return True

    healthy = True
    for unit, description in CRITICAL_TIMERS:
        if service_active(unit):
            logger(f"{description} ({unit}) active")
        else:
            logger(f"{description} ({unit}) inactive")
            healthy = False
    return healthy


def _format_duration(delta: timedelta) -> str:
    total_seconds = int(max(delta.total_seconds(), 0))
    days, remainder = divmod(total_seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _parse_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def check_alert_stats(
    logger: Callable[[str], None],
    warn_after: timedelta,
) -> bool:
    """Validate IDS telemetry state and warn when stale or unreadable."""

    if not ALERT_STATS.exists():
        logger(f"Alert statistics missing at {ALERT_STATS}")
        return False

    try:
        raw = ALERT_STATS.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read {ALERT_STATS}: {exc}")
        return False

    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        logger(f"Corrupted JSON in {ALERT_STATS}")
        return False

    try:
        stat = ALERT_STATS.stat()
    except OSError as exc:
        logger(f"Unable to stat {ALERT_STATS}: {exc}")
        stat = None

    now = datetime.now(timezone.utc)
    if stat is not None:
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        age = now - mtime
        logger(f"alert_stats.json updated {_format_duration(age)} ago")
        if age > warn_after:
            logger(
                f"Alert statistics older than {_format_duration(warn_after)};"
                " capture service may be stalled"
            )

    last_alert = _parse_timestamp(str(data.get("last_alert", "")))
    if last_alert is not None:
        logger(
            f"Last alert recorded {_format_duration(now - last_alert)} ago"
        )

    totals = [
        ("total_alerts", "Total alerts"),
        ("high_confidence", "High-confidence alerts"),
        ("low_confidence", "Low-confidence alerts"),
    ]
    for key, label in totals:
        value = data.get(key)
        if isinstance(value, int):
            logger(f"{label}: {value}")

    return True


def check_model(logger: Callable[[str], None]) -> bool:
    if not MODEL.exists():
        logger("IDS model missing; training may have failed")
        return False
    try:
        size = MODEL.stat().st_size
    except OSError as exc:
        logger(f"Unable to stat IDS model: {exc}")
        return False
    if size == 0:
        logger("IDS model file is empty")
        return False
    logger(f"IDS model present ({size // 1024} KiB)")
    return True


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Only report inactive services; do not attempt automatic restarts.",
    )
    parser.add_argument(
        "--stale-minutes",
        type=int,
        default=60,
        help="Warn when alert statistics are older than this many minutes (default: 60).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Echo log messages to stdout in addition to the log file.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logger = create_logger(args.verbose)
    warn_after = timedelta(minutes=max(args.stale_minutes, 1))

    status_checks: Iterable[bool] = (
        check_model(logger),
        check_alert_stats(logger, warn_after),
        check_services(logger, restart=not args.no_restart),
        check_timers(logger),
    )
    return 0 if all(status_checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
