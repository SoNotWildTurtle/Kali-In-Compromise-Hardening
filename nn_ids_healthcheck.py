#!/usr/bin/env python3
"""Run a focused set of health checks for the neural network IDS stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pwd
import grp
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

MODEL = Path("/opt/nnids/ids_model.pkl")
ALERT_STATS = Path("/var/lib/nn_ids/alert_stats.json")
LOG = Path("/var/log/nn_ids_health.log")
MINUTE_FORMAT = "%Y-%m-%dT%H:%MZ"
RECENT_ALERT_MAX_ENTRIES = 512
RECENT_ALERT_TOLERANCE = timedelta(seconds=60)
PROBABILITY_TOLERANCE = 0.01
PROBABILITY_BUCKET_TOLERANCE = 1e-6
DRIFT_BOUND = 1.0
MODEL_AGE_DAYS_TOLERANCE = 0.5
MODEL_TIMESTAMP_TOLERANCE = timedelta(hours=2)
MODEL_CLOCK_SKEW_TOLERANCE = timedelta(minutes=15)

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

CONFIG_CANDIDATES: Sequence[Path] = (
    Path("/etc/nn_ids.conf"),
    Path("/opt/nnids/nn_ids.conf"),
    Path(__file__).resolve().parent / "nn_ids.conf",
)

PROTECTED_PATHS: Sequence[Tuple[Path, str]] = (
    (ALERT_STATS.parent, "Alert telemetry directory"),
    (ALERT_STATS, "Alert telemetry"),
    (MODEL.parent, "Model artifact directory"),
    (MODEL, "Model artifact"),
    (LOG.parent, "Health log directory"),
    (LOG, "Health log"),
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


def _format_mode(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def _format_owner(uid: int, gid: int) -> str:
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = str(gid)
    return f"{user}:{group}"


def _check_secure_path(
    path: Path,
    label: str,
    logger: Callable[[str], None],
) -> bool:
    """Validate ownership and permissions for security-sensitive assets."""

    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        logger(f"{label} missing ({path})")
        return False
    except OSError as exc:
        logger(f"Unable to stat {label} ({path}): {exc}")
        return False

    healthy = True
    mode = stat_result.st_mode
    owner = _format_owner(stat_result.st_uid, stat_result.st_gid)
    mode_text = _format_mode(mode)

    if stat.S_ISLNK(mode):
        logger(f"{label} is a symbolic link ({path}); replace with a regular file")
        healthy = False

    permissions = stat.S_IMODE(mode)
    if permissions & stat.S_IWOTH:
        logger(
            f"{label} is world-writable (mode {mode_text}); tighten permissions on {path}"
        )
        healthy = False
    if permissions & stat.S_IWGRP:
        logger(
            f"{label} is group-writable (mode {mode_text}); restrict group write access"
        )
        healthy = False

    allowed_uids = {0, os.getuid()}
    if stat_result.st_uid not in allowed_uids:
        logger(
            f"{label} owned by {owner}; expected root or the invoking user for {path}"
        )
        healthy = False

    if healthy:
        logger(f"{label} permissions secure ({owner} {mode_text})")

    return healthy


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


def unit_enabled(unit: str) -> Tuple[bool, str]:
    """Return whether a systemd unit is enabled and the reported state."""

    if not SYSTEMCTL_AVAILABLE:
        return False, "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", unit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return False, f"error: {exc}"

    output = (result.stdout or result.stderr or "").strip() or "disabled"
    if result.returncode == 0:
        return True, output
    return False, output


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


def check_unit_enablement(logger: Callable[[str], None]) -> bool:
    """Verify that critical services and timers are enabled for startup."""

    if not _systemctl_available(logger):
        return True

    healthy = True
    checked: set[str] = set()
    acceptable_states = {"enabled", "linked", "alias", "static", "indirect", "generated"}

    for unit_group in (CRITICAL_SERVICES, CRITICAL_TIMERS):
        for unit, description in unit_group:
            if unit in checked:
                continue
            checked.add(unit)
            enabled, state = unit_enabled(unit)
            state_lower = state.lower()
            if enabled or state_lower in acceptable_states:
                logger(
                    f"{description} ({unit}) enablement: {state_lower or 'enabled'}"
                )
                continue
            healthy = False
            if state_lower == "unknown":
                logger(f"Unable to determine enablement for {description} ({unit})")
            else:
                logger(
                    f"{description} ({unit}) not enabled (state: {state_lower});"
                    " enable or intentionally mask to avoid startup gaps"
                )

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


def _parse_minute_bucket(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.strptime(value, MINUTE_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _compute_file_sha256(path: Path) -> Optional[str]:
    """Return the SHA-256 hex digest for ``path`` or ``None`` on failure."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _parse_probability_bucket_label(label: str) -> Optional[Tuple[float, float]]:
    """Convert a probability bucket label ("0.90-1.00") into numeric bounds."""

    if not isinstance(label, str):
        return None
    parts = label.split("-", 1)
    if len(parts) != 2:
        return None
    try:
        lower = float(parts[0].strip())
        upper = float(parts[1].strip())
    except (TypeError, ValueError):
        return None
    if not 0.0 <= lower < upper <= 1.0:
        return None
    return lower, upper


def _validate_int_field(
    data: Dict[str, object],
    key: str,
    label: str,
    logger: Callable[[str], None],
    *,
    required: bool,
) -> Tuple[Optional[int], bool]:
    """Extract and validate a non-negative integer field from telemetry."""

    value = data.get(key)
    if value is None:
        if required:
            logger(f"{label} missing from telemetry")
            return None, False
        return None, True
    if isinstance(value, bool) or not isinstance(value, int):
        logger(
            f"{label} counter has unexpected type {type(value).__name__};"
            " investigate telemetry writer"
        )
        return None, False
    if value < 0:
        logger(f"{label} counter is negative; telemetry may be corrupt")
        return None, False
    return int(value), True


def _validate_float_field(
    data: Dict[str, object],
    key: str,
    label: str,
    logger: Callable[[str], None],
    *,
    required: bool,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
) -> Tuple[Optional[float], bool]:
    """Extract and validate a finite float field from telemetry."""

    value = data.get(key)
    if value is None:
        if required:
            logger(f"{label} missing from telemetry")
            return None, False
        return None, True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        logger(
            f"{label} value has unexpected type {type(value).__name__};"
            " investigate telemetry writer"
        )
        return None, False
    number = float(value)
    if not math.isfinite(number):
        logger(f"{label} value is not a finite number")
        return None, False
    if min_value is not None and number < min_value:
        logger(f"{label} below expected minimum {min_value}")
        return None, False
    if max_value is not None and number > max_value:
        logger(f"{label} exceeds expected maximum {max_value}")
        return None, False
    return number, True


def _extract_counter_map(
    data: Dict[str, object],
    key: str,
    label: str,
    logger: Callable[[str], None],
    *,
    required: bool,
    max_entries: int = 256,
) -> Tuple[Dict[str, int], bool]:
    value = data.get(key)
    if value is None:
        if required:
            logger(f"{label} map missing from telemetry")
            return {}, False
        return {}, True
    if not isinstance(value, dict):
        logger(f"{label} map has unexpected type {type(value).__name__}")
        return {}, False

    healthy = True
    sanitized: Dict[str, int] = {}
    if len(value) > max_entries:
        logger(
            f"{label} map contains {len(value)} entries; trimming may have failed"
        )
        healthy = False

    for entry_key, entry_value in value.items():
        if not isinstance(entry_key, str):
            logger(f"{label} map has non-string key {entry_key!r}")
            healthy = False
            continue
        if isinstance(entry_value, bool) or not isinstance(entry_value, int):
            logger(
                f"{label} map entry {entry_key!r} has invalid count"
                f" ({type(entry_value).__name__})"
            )
            healthy = False
            continue
        if entry_value < 0:
            logger(f"{label} map entry {entry_key!r} is negative")
            healthy = False
            continue
        sanitized[entry_key] = int(entry_value)

    return sanitized, healthy


def _validate_counter_map(
    data: Dict[str, object],
    key: str,
    label: str,
    logger: Callable[[str], None],
    *,
    required: bool,
    max_entries: int = 256,
) -> bool:
    """Ensure a telemetry dictionary contains sane string->int counts."""

    _, healthy = _extract_counter_map(
        data,
        key,
        label,
        logger,
        required=required,
        max_entries=max_entries,
    )
    return healthy


def _validate_recent_alerts(
    data: Dict[str, Any],
    logger: Callable[[str], None],
    *,
    now: datetime,
) -> Tuple[Optional[datetime], Optional[str], Optional[float], bool]:
    """Ensure recent alert entries are well-formed and return latest details."""

    recent = data.get("recent_alerts")
    if recent is None:
        return None, None, None, True
    if not isinstance(recent, list):
        logger("recent_alerts field has unexpected structure; expected list")
        return None, None, None, False

    healthy = True
    if len(recent) > RECENT_ALERT_MAX_ENTRIES:
        logger(
            f"recent_alerts contains {len(recent)} entries; telemetry trimming may be failing"
        )
        healthy = False

    latest_timestamp: Optional[datetime] = None
    latest_reason: Optional[str] = None
    latest_probability: Optional[float] = None
    previous_timestamp: Optional[datetime] = None

    for index, entry in enumerate(recent):
        if not isinstance(entry, dict):
            logger(f"recent_alerts entry {index} is not an object")
            healthy = False
            continue

        raw_time = entry.get("time")
        timestamp: Optional[datetime] = None
        if isinstance(raw_time, str):
            timestamp = _parse_timestamp(raw_time)
        if timestamp is None:
            logger(f"recent_alerts entry {index} has invalid or missing timestamp")
            healthy = False
        else:
            if timestamp > now + RECENT_ALERT_TOLERANCE:
                skew = timestamp - now
                logger(
                    f"recent_alerts entry {index} timestamp {raw_time!r} appears"
                    f" {_format_duration(skew)} ahead of system clock"
                )
                healthy = False
            if previous_timestamp is not None and timestamp < previous_timestamp:
                logger(
                    f"recent_alerts entry {index} timestamp out of order; entries should be chronological"
                )
                healthy = False
            if previous_timestamp is None or timestamp >= previous_timestamp:
                previous_timestamp = timestamp

        for endpoint in ("src", "dst"):
            endpoint_value = entry.get(endpoint)
            if endpoint_value is None or not str(endpoint_value).strip():
                logger(f"recent_alerts entry {index} missing {endpoint} address")
                healthy = False

        reason_value: Optional[str] = None
        for key in ("reason", "canonical_reason"):
            candidate = entry.get(key)
            if isinstance(candidate, str) and candidate.strip():
                reason_value = candidate.strip()
                break
        if reason_value is None:
            logger(f"recent_alerts entry {index} missing classification reason")
            healthy = False

        probability_value = entry.get("probability")
        probability: Optional[float] = None
        if probability_value is not None:
            if isinstance(probability_value, bool) or not isinstance(
                probability_value, (int, float)
            ):
                logger(
                    f"recent_alerts entry {index} probability has unexpected type"
                )
                healthy = False
            else:
                probability = float(probability_value)
                if not math.isfinite(probability):
                    logger(
                        f"recent_alerts entry {index} probability is not a finite number"
                    )
                    healthy = False
                    probability = None
                elif not 0.0 <= probability <= 1.0:
                    logger(
                        f"recent_alerts entry {index} probability out of range [0, 1]"
                    )
                    healthy = False
                    probability = None

        if timestamp is not None and (
            latest_timestamp is None or timestamp >= latest_timestamp
        ):
            latest_timestamp = timestamp
            latest_reason = reason_value
            latest_probability = probability

    return latest_timestamp, latest_reason, latest_probability, healthy


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

    if not isinstance(data, dict):
        logger(f"Unexpected structure in {ALERT_STATS}; expected JSON object")
        return False

    healthy = True

    try:
        stat = ALERT_STATS.stat()
    except OSError as exc:
        logger(f"Unable to stat {ALERT_STATS}: {exc}")
        stat = None

    now = datetime.now(timezone.utc)
    try:
        model_stat = MODEL.stat()
    except OSError:
        model_stat = None
    model_mtime = (
        datetime.fromtimestamp(model_stat.st_mtime, timezone.utc)
        if model_stat is not None
        else None
    )
    model_size = model_stat.st_size if model_stat is not None else None
    if stat is not None:
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        age = now - mtime
        logger(f"alert_stats.json updated {_format_duration(age)} ago")
        if age > warn_after:
            logger(
                f"Alert statistics older than {_format_duration(warn_after)};"
                " capture service may be stalled"
            )
            healthy = False

    last_alert_raw = data.get("last_alert", "")
    last_alert = _parse_timestamp(str(last_alert_raw))
    if last_alert is None:
        if last_alert_raw:
            logger("Unable to parse last_alert timestamp from telemetry")
        else:
            logger("No last_alert timestamp present in telemetry")
        healthy = False
    else:
        delay = now - last_alert
        logger(f"Last alert recorded {_format_duration(delay)} ago")
        if delay > warn_after:
            logger(
                f"Last alert timestamp older than {_format_duration(warn_after)};"
                " review capture and inference pipeline"
            )
            healthy = False
        if last_alert > now + RECENT_ALERT_TOLERANCE:
            skew = last_alert - now
            logger(
                "last_alert timestamp is"
                f" {_format_duration(skew)} ahead of system clock;"
                " verify time synchronisation"
            )
            healthy = False

    last_probability, prob_ok = _validate_float_field(
        data,
        "last_probability",
        "Last alert probability",
        logger,
        required=False,
        min_value=0.0,
        max_value=1.0,
    )
    healthy = healthy and prob_ok
    if last_probability is not None:
        logger(f"Last alert probability: {last_probability:.3f}")

    reason_value = data.get("last_reason")
    canonical_reason_value = data.get("last_canonical_reason")
    last_reason: Optional[str] = None
    if reason_value is not None:
        if not isinstance(reason_value, str):
            logger(
                "last_reason field has unexpected type"
                f" {type(reason_value).__name__}"
            )
            healthy = False
        elif reason_value.strip():
            last_reason = reason_value.strip()
    if canonical_reason_value is not None:
        if not isinstance(canonical_reason_value, str):
            logger(
                "last_canonical_reason field has unexpected type"
                f" {type(canonical_reason_value).__name__}"
            )
            healthy = False
        elif canonical_reason_value.strip():
            canonical_reason = canonical_reason_value.strip()
            if last_reason is None:
                last_reason = canonical_reason
            elif canonical_reason != last_reason:
                logger(
                    "last_reason and last_canonical_reason diverge;"
                    " telemetry metadata inconsistent"
                )
                healthy = False

    (
        latest_recent_alert,
        recent_reason,
        recent_probability,
        recent_ok,
    ) = _validate_recent_alerts(data, logger, now=now)
    healthy = healthy and recent_ok
    if latest_recent_alert is not None:
        if last_alert is None:
            logger("recent_alerts contain data but last_alert is missing")
            healthy = False
        else:
            delta_seconds = abs(
                (last_alert - latest_recent_alert).total_seconds()
            )
            if delta_seconds > RECENT_ALERT_TOLERANCE.total_seconds():
                logger(
                    "last_alert timestamp does not align with most recent"
                    " recent_alerts entry"
                )
                healthy = False
    if recent_reason:
        if last_reason is None:
            logger(
                "Recent alert reason not reflected in last_reason metadata"
            )
            healthy = False
        elif last_reason != recent_reason:
            logger(
                "last_reason does not match most recent alert classification"
            )
            healthy = False
    if (
        recent_probability is not None
        and last_probability is not None
        and abs(last_probability - recent_probability) > PROBABILITY_TOLERANCE
    ):
        logger(
            "last_probability diverges from recent_alerts probability;"
            " telemetry writer lagging"
        )
        healthy = False

    total_alerts, total_ok = _validate_int_field(
        data, "total_alerts", "Total alerts", logger, required=True
    )
    healthy = healthy and total_ok
    if total_ok and total_alerts is not None:
        logger(f"Total alerts: {total_alerts}")

    high_confidence, high_ok = _validate_int_field(
        data, "high_confidence", "High-confidence alerts", logger, required=True
    )
    healthy = healthy and high_ok
    if high_ok and high_confidence is not None:
        logger(f"High-confidence alerts: {high_confidence}")

    low_confidence, low_ok = _validate_int_field(
        data, "low_confidence", "Low-confidence alerts", logger, required=True
    )
    healthy = healthy and low_ok
    if low_ok and low_confidence is not None:
        logger(f"Low-confidence alerts: {low_confidence}")

    if (
        total_alerts is not None
        and high_confidence is not None
        and low_confidence is not None
    ):
        expected_total = high_confidence + low_confidence
        if total_alerts < expected_total:
            logger(
                "Total alerts counter is lower than combined high/low totals;"
                " investigate data loss"
            )
            healthy = False
        elif total_alerts > expected_total:
            logger(
                "Total alerts counter exceeds high/low combined totals;"
                " telemetry writer may be miscounting"
            )
            healthy = False

    streak_fields = (
        ("current_high_streak", "Current high-confidence streak"),
        ("current_low_streak", "Current low-confidence streak"),
        ("longest_high_streak", "Longest high-confidence streak"),
        ("longest_low_streak", "Longest low-confidence streak"),
        ("alerts_last_hour", "Alerts in the last hour"),
        ("alerts_current_minute", "Alerts in the current minute"),
        ("zero_day_alerts", "Potential zero-day alerts"),
    )
    streak_values: Dict[str, Optional[int]] = {}
    for key, label in streak_fields:
        value, ok = _validate_int_field(data, key, label, logger, required=False)
        streak_values[key] = value
        healthy = healthy and ok

    alerts_last_hour = streak_values.get("alerts_last_hour")
    if (
        alerts_last_hour is not None
        and total_alerts is not None
        and alerts_last_hour > total_alerts
    ):
        logger(
            "Alerts in the last hour exceed total alerts recorded;"
            " telemetry aggregation inconsistent"
        )
        healthy = False

    alerts_current_minute = streak_values.get("alerts_current_minute")
    if (
        alerts_last_hour is not None
        and alerts_current_minute is not None
        and alerts_current_minute > alerts_last_hour
    ):
        logger(
            "Current minute alert counter exceeds last-hour aggregate;"
            " telemetry windowing inconsistent"
        )
        healthy = False

    zero_day_alerts = streak_values.get("zero_day_alerts")
    if (
        zero_day_alerts is not None
        and total_alerts is not None
        and zero_day_alerts > total_alerts
    ):
        logger(
            "Zero-day alert counter exceeds total alerts;"
            " investigate telemetry corruption"
        )
        healthy = False

    current_high = streak_values.get("current_high_streak")
    longest_high = streak_values.get("longest_high_streak")
    if (
        current_high is not None
        and longest_high is not None
        and current_high > longest_high
    ):
        logger("Current high-confidence streak exceeds recorded longest streak")
        healthy = False
    if (
        longest_high is not None
        and total_alerts is not None
        and longest_high > total_alerts
    ):
        logger("Longest high-confidence streak exceeds total alerts")
        healthy = False

    current_low = streak_values.get("current_low_streak")
    longest_low = streak_values.get("longest_low_streak")
    if (
        current_low is not None
        and longest_low is not None
        and current_low > longest_low
    ):
        logger("Current low-confidence streak exceeds recorded longest streak")
        healthy = False
    if (
        longest_low is not None
        and total_alerts is not None
        and longest_low > total_alerts
    ):
        logger("Longest low-confidence streak exceeds total alerts")
        healthy = False

    other_map_fields = (
        ("sources", "Source address counts"),
        ("destinations", "Destination address counts"),
        ("destination_ports", "Destination port counts"),
        ("protocols", "Protocol counts"),
    )
    for key, label in other_map_fields:
        _, ok = _extract_counter_map(
            data,
            key,
            label,
            logger,
            required=False,
        )
        healthy = healthy and ok

    reason_counts, reason_ok = _extract_counter_map(
        data,
        "reason_counts",
        "Alert reason counts",
        logger,
        required=True,
    )
    healthy = healthy and reason_ok
    if total_alerts is not None and reason_ok:
        reason_total = sum(reason_counts.values())
        if reason_total != total_alerts:
            logger(
                "Sum of alert reasons does not match total alerts;"
                " telemetry aggregation drift detected"
            )
            healthy = False
        if recent_reason:
            candidates = {recent_reason}
            if last_reason:
                candidates.add(last_reason)
            if not any(reason_counts.get(candidate, 0) > 0 for candidate in candidates):
                logger(
                    "Recent alert reason not represented in reason_counts aggregate;"
                    " telemetry reducer lagging"
                )
                healthy = False

    minute_counts, minute_ok = _extract_counter_map(
        data,
        "minute_counts",
        "Per-minute alert counts",
        logger,
        required=False,
        max_entries=512,
    )
    healthy = healthy and minute_ok

    parsed_buckets: List[Tuple[datetime, str, int]] = []
    for label, count in minute_counts.items():
        bucket_time = _parse_minute_bucket(label)
        if bucket_time is None:
            logger(
                f"minute_counts bucket {label!r} is not in expected format {MINUTE_FORMAT}"
            )
            healthy = False
            continue
        parsed_buckets.append((bucket_time, label, count))

    if parsed_buckets:
        parsed_buckets.sort(key=lambda item: item[0])
        future_cutoff = now + timedelta(minutes=1)
        for bucket_time, label, _ in parsed_buckets:
            if bucket_time > future_cutoff:
                logger(
                    f"minute_counts bucket {label} is timestamped in the future;"
                    " verify time synchronization"
                )
                healthy = False

        minute_total = sum(count for _, _, count in parsed_buckets)
        if total_alerts is not None and minute_total > total_alerts:
            logger(
                "Aggregated minute_counts exceed total alerts;"
                " telemetry retention window inconsistent"
            )
            healthy = False

        computed_last_hour = sum(
            count
            for bucket_time, _, count in parsed_buckets
            if bucket_time >= now - timedelta(hours=1)
        )
        if (
            alerts_last_hour is not None
            and computed_last_hour != alerts_last_hour
        ):
            logger(
                "alerts_last_hour does not match recomputed per-minute totals;"
                " investigate aggregation"
            )
            healthy = False

        if alerts_current_minute is not None:
            current_minute_label = (
                now.astimezone(timezone.utc)
                .replace(second=0, microsecond=0)
                .strftime(MINUTE_FORMAT)
            )
            bucket_value = 0
            for _, label, count in parsed_buckets:
                if label == current_minute_label:
                    bucket_value = count
                    break
            if bucket_value != alerts_current_minute:
                logger(
                    "alerts_current_minute diverges from minute_counts bucket;"
                    " telemetry writer misaligned"
                )
                healthy = False

        if latest_recent_alert is not None and latest_recent_alert >= now - timedelta(hours=1):
            recent_minute_label = (
                latest_recent_alert.astimezone(timezone.utc)
                .replace(second=0, microsecond=0)
                .strftime(MINUTE_FORMAT)
            )
            minute_bucket = minute_counts.get(recent_minute_label)
            if minute_bucket is None:
                logger(
                    "minute_counts missing bucket for minute containing most recent alert;"
                    " telemetry retention gap"
                )
                healthy = False
            elif minute_bucket <= 0:
                logger(
                    "minute_counts bucket for most recent alert minute reports zero alerts"
                )
                healthy = False

    peak_minute_label = data.get("peak_minute_label")
    peak_minute_count, peak_ok = _validate_int_field(
        data,
        "peak_minute_count",
        "Peak minute count",
        logger,
        required=False,
    )
    healthy = healthy and peak_ok

    for field, label, minimum, maximum in (
        (
            "model_drift_delta",
            "Model drift delta",
            -DRIFT_BOUND,
            DRIFT_BOUND,
        ),
        (
            "global_probability_trend",
            "Global probability trend",
            -DRIFT_BOUND,
            DRIFT_BOUND,
        ),
        ("prob_stddev", "Probability standard deviation", 0.0, 1.0),
        ("average_probability", "Average probability", 0.0, 1.0),
        ("global_ewma_probability", "Global EWMA probability", 0.0, 1.0),
        ("recent_probability_average", "Recent probability average", 0.0, 1.0),
    ):
        _, float_ok = _validate_float_field(
            data,
            field,
            label,
            logger,
            required=False,
            min_value=minimum,
            max_value=maximum,
        )
        healthy = healthy and float_ok
    if peak_minute_label is not None:
        if not isinstance(peak_minute_label, str):
            logger(
                "peak_minute_label field has unexpected type"
                f" {type(peak_minute_label).__name__}"
            )
            healthy = False
        else:
            peak_bucket = _parse_minute_bucket(peak_minute_label)
            if peak_bucket is None:
                logger(
                    f"peak_minute_label {peak_minute_label!r} is not in format {MINUTE_FORMAT}"
                )
                healthy = False
            if peak_minute_count is not None:
                bucket_value = minute_counts.get(peak_minute_label)
                if bucket_value is None:
                    logger(
                        "peak_minute_label not present in minute_counts;"
                        " telemetry may be desynchronised"
                    )
                    healthy = False
                if bucket_value is not None and bucket_value != peak_minute_count:
                    logger(
                        "peak_minute_count does not match stored minute_counts bucket"
                    )
                    healthy = False
    elif peak_minute_count not in (None, 0):
        logger(
            "peak_minute_count present without matching peak_minute_label;"
            " telemetry metadata inconsistent"
        )
        healthy = False

    if peak_minute_count is not None:
        if total_alerts is not None and peak_minute_count > total_alerts:
            logger("Peak minute count exceeds total alerts recorded")
            healthy = False
        if alerts_last_hour is not None and peak_minute_count > alerts_last_hour:
            logger("Peak minute count exceeds last-hour aggregate")
            healthy = False

    recent_history, history_ok = _extract_counter_map(
        data,
        "recent_alert_history",
        "Recent alert history",
        logger,
        required=False,
        max_entries=512,
    )
    healthy = healthy and history_ok
    if history_ok and recent_history:
        history_total = sum(recent_history.values())
        if history_total < 0:
            logger("Recent alert history produced negative totals")
            healthy = False
        elif (
            alerts_last_hour is not None
            and history_total < alerts_last_hour
        ):
            logger(
                "Recent alert history under-reports alerts seen in the last hour;"
                " telemetry retention window too small?"
            )
            healthy = False

    probability_buckets, buckets_ok = _extract_counter_map(
        data,
        "probability_buckets",
        "Probability buckets",
        logger,
        required=False,
        max_entries=32,
    )
    healthy = healthy and buckets_ok
    if buckets_ok and probability_buckets and total_alerts is not None:
        bucket_total = sum(probability_buckets.values())
        if bucket_total != total_alerts:
            logger(
                "Probability bucket aggregation does not match total alerts;"
                " investigate telemetry reducer"
            )
            healthy = False
    if buckets_ok and probability_buckets:
        parsed_ranges: List[Tuple[float, float, str, int]] = []
        for label, count in probability_buckets.items():
            parsed = _parse_probability_bucket_label(label)
            if parsed is None:
                logger(
                    f"Probability bucket label {label!r} not in expected range format;"
                    " reducer misconfigured"
                )
                healthy = False
                continue
            parsed_ranges.append((parsed[0], parsed[1], label, count))

        if parsed_ranges:
            parsed_ranges.sort(key=lambda item: (item[0], item[1]))
            first_lower = parsed_ranges[0][0]
            last_upper = parsed_ranges[-1][1]
            if first_lower > PROBABILITY_BUCKET_TOLERANCE:
                logger(
                    "Probability buckets do not start near 0.0;"
                    " low-confidence coverage missing"
                )
                healthy = False
            if last_upper < 1.0 - PROBABILITY_BUCKET_TOLERANCE:
                logger(
                    "Probability buckets stop short of 1.0;"
                    " high-confidence coverage truncated"
                )
                healthy = False

            previous_upper: Optional[float] = None
            previous_label: Optional[str] = None
            for lower, upper, label, _ in parsed_ranges:
                if previous_upper is not None:
                    if lower - PROBABILITY_BUCKET_TOLERANCE > previous_upper:
                        logger(
                            "Probability buckets leave coverage gap between"
                            f" {previous_label or 'previous bucket'} and {label};"
                            f" coverage missing from {previous_upper:.2f} to {lower:.2f}"
                        )
                        healthy = False
                    if lower + PROBABILITY_BUCKET_TOLERANCE < previous_upper:
                        logger(
                            f"Probability bucket {label} overlaps with a previous range;"
                            " reducer bins misordered"
                        )
                        healthy = False
                previous_upper = upper
                previous_label = label

            if recent_probability is not None:
                matched_label: Optional[str] = None
                matched_count: Optional[int] = None
                for lower, upper, label, count in parsed_ranges:
                    upper_bound = upper + PROBABILITY_BUCKET_TOLERANCE
                    if lower - PROBABILITY_BUCKET_TOLERANCE <= recent_probability <= upper_bound:
                        matched_label = label
                        matched_count = count
                        break
                if matched_label is None:
                    logger(
                        "Recent alert probability not represented in probability_buckets;"
                        " reducer lagging"
                    )
                    healthy = False
                elif matched_count is not None and matched_count <= 0:
                    logger(
                        f"Probability bucket {matched_label} reports zero alerts despite recent event"
                    )
                    healthy = False

    hourly_distribution, hourly_ok = _extract_counter_map(
        data,
        "hourly_distribution",
        "Hourly alert distribution",
        logger,
        required=False,
        max_entries=48,
    )
    healthy = healthy and hourly_ok
    hourly_counts_by_hour: Dict[int, int] = {}
    if hourly_ok and hourly_distribution:
        if len(hourly_distribution) > 24:
            logger(
                "hourly_distribution contains more than 24 entries;"
                " retention window may be corrupted"
            )
            healthy = False
        for label, count in hourly_distribution.items():
            try:
                hour = int(label)
            except (TypeError, ValueError):
                logger(
                    f"hourly_distribution label {label!r} is not an integer hour"
                    " telemetry map malformed"
                )
                healthy = False
                continue
            if not 0 <= hour <= 23:
                logger(
                    f"hourly_distribution label {label!r} outside range 0-23;"
                    " investigate telemetry normalisation"
                )
                healthy = False
                continue
            hourly_counts_by_hour[hour] = int(count)

        if alerts_last_hour is not None and alerts_last_hour > 0:
            current_hour = now.astimezone(timezone.utc).hour
            bucket = hourly_counts_by_hour.get(current_hour)
            if bucket is None:
                logger(
                    "hourly_distribution missing current hour despite alerts in the last hour;"
                    " telemetry reducer lagging"
                )
                healthy = False
            elif bucket <= 0:
                logger(
                    "hourly_distribution reports zero alerts for current hour despite recent activity"
                )
                healthy = False

        if latest_recent_alert is not None:
            recent_hour = latest_recent_alert.astimezone(timezone.utc).hour
            bucket = hourly_counts_by_hour.get(recent_hour)
            if bucket is None:
                logger(
                    "hourly_distribution missing hour covering most recent alert;"
                    " telemetry retention gap"
                )
                healthy = False
            elif bucket <= 0:
                logger(
                    "hourly_distribution reports zero alerts for hour containing most recent alert"
                )
                healthy = False

    if hourly_ok and hourly_distribution and alerts_last_hour is not None:
        hourly_total = sum(hourly_distribution.values())
        if hourly_total < alerts_last_hour:
            logger(
                "Hourly distribution totals fewer alerts than the last-hour aggregate;"
                " history window may be truncated"
            )
            healthy = False

    model_health = data.get("model_health")
    if model_health is not None:
        if not isinstance(model_health, str):
            logger(
                "model_health field has unexpected type"
                f" {type(model_health).__name__}"
            )
            healthy = False
        elif model_health not in {"nominal", "watch", "degraded"}:
            logger(f"model_health has unknown state '{model_health}'")
            healthy = False

    model_info = data.get("model_info")
    if model_info is not None:
        if not isinstance(model_info, dict):
            logger("model_info field has unexpected structure; expected object")
            healthy = False
        else:
            age_days, age_ok = _validate_float_field(
                model_info,
                "age_days",
                "Model info age (days)",
                logger,
                required=False,
                min_value=0.0,
            )
            healthy = healthy and age_ok

            refresh_value = model_info.get("refresh_recommended")
            if refresh_value is not None and not isinstance(refresh_value, bool):
                logger(
                    "model_info.refresh_recommended field has unexpected type"
                    f" {type(refresh_value).__name__}"
                )
                healthy = False

            last_trained: Optional[datetime] = None
            last_trained_value = model_info.get("last_trained")
            if last_trained_value:
                if not isinstance(last_trained_value, str):
                    logger(
                        "model_info.last_trained field has unexpected type"
                        f" {type(last_trained_value).__name__}"
                    )
                    healthy = False
                else:
                    parsed_trained = _parse_timestamp(last_trained_value)
                    if parsed_trained is None:
                        logger("model_info.last_trained is not a valid timestamp")
                        healthy = False
                    else:
                        last_trained = parsed_trained
                        if last_trained > now + MODEL_CLOCK_SKEW_TOLERANCE:
                            skew = last_trained - now
                            logger(
                                "model_info.last_trained timestamp is",
                                f" {_format_duration(skew)} ahead of system clock;",
                                " verify training pipeline time sync",
                            )
                            healthy = False
            else:
                logger("model_info.last_trained missing from telemetry metadata")
                healthy = False

            if model_mtime is None:
                if MODEL.exists():
                    logger(
                        "Unable to reconcile model metadata with model artifact timestamp;"
                        " inspect file permissions"
                    )
                else:
                    logger(
                        "Model artifact missing while model_info telemetry present;"
                        " reconcile deployment state"
                    )
                healthy = False

            if last_trained is not None and model_mtime is not None:
                delta = last_trained - model_mtime
                if delta < timedelta(0):
                    delta = -delta
                if delta > MODEL_TIMESTAMP_TOLERANCE:
                    logger(
                        "model_info.last_trained does not align with model file timestamp;"
                        f" drift of {_format_duration(delta)} detected"
                    )
                    healthy = False

            if age_ok and age_days is not None:
                reference = last_trained or model_mtime
                if reference is not None:
                    computed_age = max((now - reference).total_seconds() / 86_400.0, 0.0)
                    if abs(computed_age - age_days) > MODEL_AGE_DAYS_TOLERANCE:
                        logger(
                            "model_info age_days diverges from recorded training timestamp by"
                            f" {abs(computed_age - age_days):.2f} day(s);"
                            " metadata refresh required"
                        )
                        healthy = False

            artifact_size_value = model_info.get("artifact_size")
            artifact_size: Optional[int] = None
            if artifact_size_value is not None:
                if isinstance(artifact_size_value, bool) or not isinstance(
                    artifact_size_value, int
                ):
                    logger(
                        "model_info.artifact_size field has unexpected type",
                        f" {type(artifact_size_value).__name__}",
                    )
                    healthy = False
                elif artifact_size_value < 0:
                    logger("model_info.artifact_size is negative; metadata corruption suspected")
                    healthy = False
                else:
                    artifact_size = int(artifact_size_value)
            elif model_mtime is not None:
                logger("model_info.artifact_size missing from telemetry metadata")
                healthy = False

            if artifact_size is not None and model_size is not None:
                if artifact_size != model_size:
                    logger(
                        "model_info.artifact_size does not match model artifact size;",
                        " investigate deployment integrity",
                    )
                    healthy = False

            artifact_hash_value = model_info.get("artifact_sha256")
            normalized_hash: Optional[str] = None
            if artifact_hash_value is not None:
                if not isinstance(artifact_hash_value, str):
                    logger(
                        "model_info.artifact_sha256 field has unexpected type",
                        f" {type(artifact_hash_value).__name__}",
                    )
                    healthy = False
                else:
                    candidate = artifact_hash_value.strip().lower()
                    if len(candidate) != 64:
                        logger(
                            "model_info.artifact_sha256 must be a 64-character hex digest",
                        )
                        healthy = False
                    else:
                        try:
                            bytes.fromhex(candidate)
                        except ValueError:
                            logger("model_info.artifact_sha256 contains non-hex characters")
                            healthy = False
                        else:
                            normalized_hash = candidate
            elif model_mtime is not None:
                logger("model_info.artifact_sha256 missing from telemetry metadata")
                healthy = False

            if normalized_hash is not None:
                if model_size is None:
                    logger(
                        "model_info.artifact_sha256 present but model artifact metadata unavailable",
                    )
                    healthy = False
                else:
                    computed_hash = _compute_file_sha256(MODEL)
                    if computed_hash is None:
                        logger("Unable to compute model artifact hash for comparison")
                        healthy = False
                    elif computed_hash != normalized_hash:
                        logger(
                            "model_info.artifact_sha256 does not match computed model artifact hash;",
                            " investigate possible tampering",
                        )
                        healthy = False

            info_health = model_info.get("health")
            if info_health is not None:
                if not isinstance(info_health, str):
                    logger(
                        "model_info.health field has unexpected type"
                        f" {type(info_health).__name__}"
                    )
                    healthy = False
                elif model_health is not None and info_health != model_health:
                    logger(
                        "model_info.health does not align with model_health field"
                    )
                    healthy = False

            for field, label in (
                ("global_average_probability", "Model info global average probability"),
                (
                    "recent_average_probability",
                    "Model info recent average probability",
                ),
            ):
                _, info_ok = _validate_float_field(
                    model_info,
                    field,
                    label,
                    logger,
                    required=False,
                    min_value=0.0,
                    max_value=1.0,
                )
                healthy = healthy and info_ok

    return healthy


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


def check_filesystem_security(logger: Callable[[str], None]) -> bool:
    """Ensure sensitive IDS assets are owned and permissioned securely."""

    seen: set[Path] = set()
    healthy = True
    for path, label in PROTECTED_PATHS:
        if path in seen:
            continue
        seen.add(path)
        if not _check_secure_path(path, label, logger):
            healthy = False

    config_found = False
    for candidate in CONFIG_CANDIDATES:
        if not (candidate.exists() or candidate.is_symlink()):
            continue
        config_found = True
        label = "IDS configuration" if candidate == CONFIG_CANDIDATES[0] else "IDS configuration candidate"
        if not _check_secure_path(candidate, label, logger):
            healthy = False
        parent = candidate.parent
        if parent not in seen:
            seen.add(parent)
            if not _check_secure_path(parent, "IDS configuration directory", logger):
                healthy = False

    if not config_found:
        locations = ", ".join(str(path) for path in CONFIG_CANDIDATES)
        logger(f"IDS configuration missing; expected one of: {locations}")
        healthy = False
    return healthy


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

    check_results: List[Tuple[str, bool]] = [
        ("Model artifact", check_model(logger)),
        ("Alert telemetry", check_alert_stats(logger, warn_after)),
        (
            "Critical services",
            check_services(logger, restart=not args.no_restart),
        ),
        ("Scheduled timers", check_timers(logger)),
        ("Systemd enablement", check_unit_enablement(logger)),
        ("Filesystem hygiene", check_filesystem_security(logger)),
    ]

    for name, result in check_results:
        logger(f"{name} check {'passed' if result else 'FAILED'}")

    overall = all(result for _, result in check_results)
    logger(f"Health check {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
