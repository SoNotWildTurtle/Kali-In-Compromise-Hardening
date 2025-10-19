#!/usr/bin/env python3
"""Interactive curses dashboard for Kali Neural IDS analytics.

This utility aggregates metrics from ``/var/lib/nn_ids/alert_stats.json`` and
related log files to present an at-a-glance status board for operators.  It is
safe to run on systems where the IDS has not generated data yet; sections will
note when information is unavailable.
"""
from __future__ import annotations

import curses
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
import textwrap
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Set

ALERT_STATS = Path("/var/lib/nn_ids/alert_stats.json")
MODEL_PATH = Path("/opt/nnids/ids_model.pkl")
CONFIG_CANDIDATES = [
    Path("/etc/nn_ids.conf"),
    Path("/opt/nnids/nn_ids.conf"),
    Path(__file__).resolve().parent / "nn_ids.conf",
]
INCIDENT_REPORT = Path("/var/log/nn_ids/incident_response_report.md")
HEALTH_LOG = Path("/var/log/nn_ids_health.log")
DEFAULT_LOGS: Dict[str, Path] = {
    "alerts": Path("/var/log/nn_ids_alerts.log"),
    "process": Path("/var/log/process_monitor_alerts.log"),
    "ga_process": Path("/var/log/ga_tech_proc_alerts.log"),
    "ga_syscall": Path("/var/log/ga_tech_sys_alerts.log"),
    "threat_feed": Path("/var/log/threat_feed_blocklist.log"),
    "resource": Path("/var/log/nn_ids_resource_monitor.log"),
    "health": HEALTH_LOG,
    "network_in": Path("/var/log/inbound_traffic.log"),
    "network_out": Path("/var/log/outbound_traffic.log"),
    "anti_wipe": Path("/var/log/anti_wipe_monitor.log"),
    "autoblock": Path("/var/log/nn_ids_autoblock.log"),
    "incident": INCIDENT_REPORT,
}
RECENT_ALERT_MAX_ENTRIES = 512
MINUTE_FORMAT = "%Y-%m-%dT%H:%MZ"
PROBABILITY_BUCKET_TOLERANCE = 1e-6
CLOCK_SKEW_TOLERANCE = timedelta(seconds=60)
MODEL_CLOCK_SKEW_TOLERANCE = timedelta(minutes=15)
MODEL_TIMESTAMP_TOLERANCE = timedelta(hours=2)
MODEL_AGE_DAYS_TOLERANCE = 0.5

SERVICES: Sequence[Tuple[str, str]] = (
    ("nn_ids.service", "Neural IDS"),
    ("nn_ids_capture.timer", "Packet capture timer"),
    ("nn_ids_retrain.timer", "Retraining timer"),
    ("nn_ids_autoblock.timer", "Autoblock timer"),
    ("threat_feed_blocklist.timer", "Threat feed timer"),
    ("nn_syscall_monitor.service", "Syscall monitor"),
    ("process_monitor.timer", "Process monitor timer"),
    ("nn_ids_resource_monitor.timer", "Resource monitor timer"),
    ("nn_ids_healthcheck.timer", "Healthcheck timer"),
    ("nn_ids_sanitize.timer", "Dataset sanitizer"),
    ("nn_ids_snapshot.timer", "Snapshot timer"),
    ("nn_ids_restore.timer", "Self-heal timer"),
)

COLOR_SUCCESS = 1
COLOR_ERROR = 2
COLOR_WARN = 3
COLOR_TITLE = 4

ENABLEMENT_OK_STATES = {"enabled", "linked", "alias"}
ENABLEMENT_ACCEPTABLE_STATES = {"static", "indirect", "generated"}

CONFIG_BOOL_KEYS = {
    "NN_IDS_NOTIFY": "Notifications",
    "NN_IDS_SANITIZE": "Packet sanitization",
    "NN_IDS_AUTOBLOCK": "Automatic IP blocking",
    "NN_IDS_THREAT_FEED": "Threat feed updates",
}

DISCOVERY_SEQUENCE = ["auto", "manual", "notify", "none"]

CONFIG_FLOAT_FIELDS = {
    "NN_IDS_THRESHOLD": ("Alert threshold", 0.0, 1.0),
    "NN_SYS_THRESHOLD": ("Syscall threshold", 0.0, 1.0),
    "GA_PROC_THRESHOLD": ("Process alert threshold", 0.0, 1.0),
    "GA_PROC_MIN_RISK": ("Process minimum risk", 0.0, 1.0),
}

CONFIG_INT_FIELDS = {
    "NN_SYS_WINDOW": ("Syscall evaluation window", 1, 4096),
}

CONFIG_DISCOVERY_KEY = "NN_IDS_DISCOVERY_MODE"
CONFIG_DISCOVERY_MODES = {"auto", "manual", "notify", "none"}


def _format_duration(delta: timedelta) -> str:
    seconds = int(max(delta.total_seconds(), 0))
    days, remainder = divmod(seconds, 86_400)
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


def _compute_file_sha256(path: Path) -> Optional[str]:
    """Return the SHA-256 digest for ``path`` or ``None`` when unreadable."""

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


def _format_mode(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def _describe_owner(uid: int, gid: int) -> str:
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = str(gid)
    return f"{user}:{group}"


def load_json(path: Path) -> Dict:
    """Load a JSON file into a dict, returning an empty dict on failure."""
    try:
        if path.exists():
            return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    except OSError:
        return {}
    return {}


def parse_config_file(path: Path) -> Tuple[Dict[str, str], List[str], List[str]]:
    data: Dict[str, str] = {}
    duplicates: List[str] = []
    malformed: List[str] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"Failed to read {path}: {exc}") from exc

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            malformed.append(f"line {idx} missing '=': {stripped}")
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        value = raw_value.split("#", 1)[0].strip()
        if not key:
            malformed.append(f"line {idx} missing key: {stripped}")
            continue
        if key in data:
            duplicates.append(f"line {idx}: duplicate key {key}")
        data[key] = value

    return data, duplicates, malformed


def detect_config_with_diagnostics() -> Tuple[Optional[Path], Dict[str, str], List[str], List[str]]:
    errors: List[str] = []
    for candidate in CONFIG_CANDIDATES:
        try:
            if candidate.exists():
                data, duplicates, malformed = parse_config_file(candidate)
                if errors:
                    malformed = list(malformed) + errors
                return candidate, data, duplicates, malformed
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        except OSError as exc:
            errors.append(f"Failed to access {candidate}: {exc}")
            continue
    return None, {}, [], errors


def detect_config() -> Tuple[Optional[Path], Dict[str, str]]:
    path, data, _, _ = detect_config_with_diagnostics()
    return path, data


def resolve_config_path() -> Path:
    path, _ = detect_config()
    if path:
        return path
    return CONFIG_CANDIDATES[-1]


def update_config_value(key: str, value: str) -> str:
    path = resolve_config_path()
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        lines = []
    except OSError as exc:
        return f"Failed to read {path}: {exc}"

    new_lines: List[str] = []
    replaced = False
    for line in lines:
        if line.strip().startswith("#"):
            new_lines.append(line)
            continue
        if line.split("=", 1)[0].strip() == key:
            new_lines.append(f"{key}={value}")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"{key}={value}")
    try:
        path.write_text("\n".join(new_lines) + "\n")
    except OSError as exc:
        return f"Failed to update {path}: {exc}"
    return f"{CONFIG_BOOL_KEYS.get(key, key)} set to {value}"


def toggle_config_bool(key: str) -> str:
    _, data = detect_config()
    current = data.get(key, "0")
    new_value = "0" if current == "1" else "1"
    label = CONFIG_BOOL_KEYS.get(key, key)
    result = update_config_value(key, new_value)
    return f"{label}: {'ON' if new_value == '1' else 'OFF'}" if "Failed" not in result else result


def cycle_discovery_mode() -> str:
    path, data = detect_config()
    current = data.get("NN_IDS_DISCOVERY_MODE", DISCOVERY_SEQUENCE[0]).lower()
    try:
        index = DISCOVERY_SEQUENCE.index(current)
    except ValueError:
        index = 0
    next_mode = DISCOVERY_SEQUENCE[(index + 1) % len(DISCOVERY_SEQUENCE)]
    message = update_config_value("NN_IDS_DISCOVERY_MODE", next_mode)
    if "Failed" in message:
        return message
    return f"Discovery mode: {next_mode}"


def prompt_user(
    stdscr: "curses._CursesWindow", prompt: str, default: Optional[str] = None
) -> Optional[str]:
    max_y, max_x = stdscr.getmaxyx()
    stdscr.nodelay(False)
    curses.echo()
    default = default or ""
    text = f"{prompt} [{default}]: "
    stdscr.addnstr(max_y - 2, 0, " " * (max_x - 1), max_x - 1)
    stdscr.addnstr(max_y - 2, 0, text[: max_x - 1], max_x - 1, curses.A_REVERSE)
    stdscr.refresh()
    try:
        response = stdscr.getstr(max_y - 2, min(len(text), max_x - 2), max_x - len(text) - 1)
    except Exception:
        result: Optional[str] = None
    else:
        decoded = response.decode(errors="ignore").strip()
        result = decoded if decoded else default
    curses.noecho()
    stdscr.nodelay(True)
    stdscr.addnstr(max_y - 2, 0, " " * (max_x - 1), max_x - 1)
    stdscr.refresh()
    return result


def set_threshold(stdscr: "curses._CursesWindow") -> str:
    _, data = detect_config()
    current = data.get("NN_IDS_THRESHOLD", "0.5")
    value = prompt_user(stdscr, "Set alert probability threshold", current)
    if value is None:
        return "Threshold update cancelled"
    try:
        number = float(value)
    except ValueError:
        return "Threshold must be numeric"
    if not 0.0 <= number <= 1.0:
        return "Threshold must be between 0 and 1"
    return update_config_value("NN_IDS_THRESHOLD", f"{number:.3f}")


def call_systemctl(unit: str) -> str:
    if not shutil.which("systemctl"):
        return "systemctl unavailable"
    result = subprocess.run(
        ["systemctl", "start", unit],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return f"Triggered {unit}"
    detail = (result.stderr or result.stdout or "error").strip()
    return f"Failed to start {unit}: {detail}"


def run_script_action(
    stdscr: "curses._CursesWindow",
    script_name: str,
    args: Optional[Sequence[str]] = None,
    python: bool = False,
) -> str:
    args = list(args or [])
    script = find_script(script_name)
    if not script:
        return f"Unable to locate {script_name}"
    command: List[str]
    if python or script.endswith(".py"):
        command = ["python3", script, *args]
    else:
        command = [script, *args]
    open_external(stdscr, command)
    return f"Executed {Path(script).name}"


def run_healthcheck(stdscr: "curses._CursesWindow") -> str:
    return run_script_action(
        stdscr,
        "nn_ids_healthcheck.py",
        ["--verbose", "--no-restart"],
        python=True,
    )


def find_script(name: str) -> Optional[str]:
    system_path = Path("/usr/local/bin") / name
    if system_path.exists():
        return str(system_path)
    local_path = Path(__file__).resolve().parent / name
    if local_path.exists():
        return str(local_path)
    return shutil.which(name)


def _status_from_systemctl(unit: str) -> str:
    if not shutil.which("systemctl"):
        return "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return "unknown"
    output = (result.stdout or result.stderr or "").strip()
    if result.returncode == 0 and output:
        return output
    if output:
        return output
    return "inactive"


def _enablement_from_systemctl(unit: str) -> str:
    if not shutil.which("systemctl"):
        return "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", unit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return "unknown"
    output = (result.stdout or result.stderr or "").strip() or "disabled"
    return output


def gather_service_lines() -> List[Tuple[str, int]]:
    lines: List[Tuple[str, int]] = []
    for unit, label in SERVICES:
        status = _status_from_systemctl(unit)
        normalized = status.lower()
        if normalized in {"active", "running"}:
            color = COLOR_SUCCESS
        elif normalized in {"failed", "inactive", "dead"}:
            color = COLOR_ERROR
        else:
            color = COLOR_WARN
        lines.append((f"{label}: {status}", color))
    if not lines:
        lines.append(("No systemd information available", COLOR_WARN))
    return lines


def gather_enablement_lines() -> List[Tuple[str, int]]:
    lines: List[Tuple[str, int]] = []
    seen: Set[str] = set()
    for unit, label in SERVICES:
        if unit in seen:
            continue
        seen.add(unit)
        state = _enablement_from_systemctl(unit)
        normalized = state.lower()
        if normalized in ENABLEMENT_OK_STATES:
            color = COLOR_SUCCESS
        elif normalized in ENABLEMENT_ACCEPTABLE_STATES or normalized == "unknown":
            color = COLOR_WARN
        elif normalized.startswith("error"):
            color = COLOR_WARN
        else:
            color = COLOR_ERROR
        display = state or "unknown"
        lines.append((f"{label}: {display}", color))
    if not lines:
        lines.append(("No enablement data available", COLOR_WARN))
    return lines


def _format_number(value) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if abs(number) >= 100 or number.is_integer():
        return f"{number:.0f}"
    if abs(number) >= 10:
        return f"{number:.1f}"
    return f"{number:.3f}"


def _sorted_items(mapping: Dict, limit: int = 5) -> List[Tuple[str, float]]:
    items: List[Tuple[str, float]] = []
    for key, value in (mapping or {}).items():
        if isinstance(value, (int, float)):
            score = float(value)
        else:
            try:
                score = float(str(value))
            except (TypeError, ValueError):
                score = 0.0
        items.append((str(key), score))
    items.sort(key=lambda pair: pair[1], reverse=True)
    return items[:limit]


def format_compact_top(mapping: Dict, label: str, limit: int = 5) -> str:
    if not mapping:
        return f"{label}: none"
    parts = [f"{key} ({_format_number(value)})" for key, value in _sorted_items(mapping, limit)]
    return f"{label}: {', '.join(parts)}"


def _coerce_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_probability_bucket(label: object) -> Optional[Tuple[float, float]]:
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


def _parse_time(value: Optional[str]) -> Optional[str]:
    dt = _coerce_datetime(value)
    if dt is None:
        return value
    local = dt.astimezone()
    return local.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_recent_alerts(stats: Dict, limit: int = 5) -> List[str]:
    entries = stats.get("recent_alerts") or []
    if not isinstance(entries, list):
        return ["No recent alerts captured yet."]
    lines: List[str] = []
    for entry in reversed(entries[-limit:]):
        time_str = _parse_time(entry.get("time")) or entry.get("time", "?")
        src = entry.get("src", "?")
        dst = entry.get("dst", "?")
        probability = entry.get("probability")
        reason = entry.get("reason") or entry.get("canonical_reason") or "unknown"
        truncated = textwrap.shorten(reason, width=60, placeholder="…")
        lines.append(
            f"{time_str} | {src} → {dst} | p={_format_number(probability)} | {truncated}"
        )
    if not lines:
        return ["No recent alerts captured yet."]
    return lines


def _latest_recent_alert(stats: Dict) -> Tuple[Optional[datetime], Optional[str], Optional[float]]:
    entries = stats.get("recent_alerts")
    if not isinstance(entries, list):
        return None, None, None

    latest_time: Optional[datetime] = None
    latest_reason: Optional[str] = None
    latest_probability: Optional[float] = None

    for entry in reversed(entries):
        if not isinstance(entry, dict):
            continue
        timestamp = _coerce_datetime(entry.get("time"))
        if timestamp is None:
            continue
        latest_time = timestamp
        reason_value = entry.get("canonical_reason") or entry.get("reason")
        if isinstance(reason_value, str) and reason_value.strip():
            latest_reason = reason_value.strip()
        probability_value = entry.get("probability")
        try:
            if probability_value is not None and probability_value != "":
                latest_probability = float(probability_value)
        except (TypeError, ValueError):
            latest_probability = None
        break

    return latest_time, latest_reason, latest_probability


def format_adversarial(stats: Dict) -> List[str]:
    lines: List[str] = []
    profile = stats.get("last_adversarial_profile")
    if isinstance(profile, dict):
        summary = [
            f"Severity: {profile.get('severity', 'unknown')}",
            f"Stage: {profile.get('stage', 'n/a')}",
            f"Tactic: {profile.get('tactic', 'n/a')}",
        ]
        recommendation = profile.get("recommendation")
        if recommendation:
            summary.append(f"Response: {recommendation}")
        lines.append(" | ".join(summary))
    else:
        lines.append("No adversarial profile recorded yet.")
    lines.append(format_compact_top(stats.get("adversarial_severity"), "Severity histogram", 4))
    lines.append(format_compact_top(stats.get("adversarial_stages"), "Stages", 4))
    lines.append(format_compact_top(stats.get("adversarial_tactics"), "Tactics", 4))
    return lines


def format_model_health(stats: Dict) -> List[str]:
    info = stats.get("model_info") or {}
    if not isinstance(info, dict):
        info = {}
    lines = [
        f"Health: {info.get('health', stats.get('model_health', 'unknown'))}",
        f"Age (days): {_format_number(info.get('age_days')) if info.get('age_days') is not None else 'unknown'}",
        f"Last trained: {info.get('last_trained', 'unknown')}",
        f"Refresh recommended: {'yes' if info.get('refresh_recommended') else 'no'}",
        f"Global avg p: {_format_number(info.get('global_average_probability'))}",
        f"Recent avg p: {_format_number(info.get('recent_average_probability'))}",
        f"Drift delta: {_format_number(stats.get('model_drift_delta'))}",
        f"Trend: {_format_number(stats.get('global_probability_trend'))}",
        f"Stddev: {_format_number(stats.get('prob_stddev'))}",
    ]
    return lines


def format_summary(stats: Dict) -> List[str]:
    total = stats.get("total_alerts", 0)
    high = stats.get("high_confidence", 0)
    low = stats.get("low_confidence", 0)
    last_time = _parse_time(stats.get("last_alert"))
    last_prob = stats.get("last_probability")
    last_reason = stats.get("last_reason") or stats.get("last_canonical_reason")
    lines = [
        f"Total alerts: {total} (high: {high} | low: {low})",
        f"Average probability: {_format_number(stats.get('average_probability'))}",
        f"Last alert: {last_time or 'n/a'}",
    ]
    if last_prob is not None or last_reason:
        lines.append(
            f"Last confidence: {_format_number(last_prob)} | Reason: {textwrap.shorten(last_reason or 'n/a', 60)}"
        )
    lines.append(
        f"High streak: {stats.get('current_high_streak', 0)} | Low streak: {stats.get('current_low_streak', 0)}"
    )
    lines.append(
        f"Low-probability streak: {stats.get('low_probability_streak', 0)}"
    )
    return lines


def format_operational_counters(stats: Dict) -> List[str]:
    def fmt(value) -> str:
        if isinstance(value, (int, float)):
            return _format_number(value)
        if value is None:
            return "unknown"
        return str(value)

    counters = [
        ("Alerts last hour", stats.get("alerts_last_hour")),
        ("Current minute", stats.get("alerts_current_minute")),
        ("Zero-day alerts", stats.get("zero_day_alerts")),
        ("Current high streak", stats.get("current_high_streak")),
        ("Current low streak", stats.get("current_low_streak")),
        ("Longest high streak", stats.get("longest_high_streak")),
        ("Longest low streak", stats.get("longest_low_streak")),
        ("Peak minute count", stats.get("peak_minute_count")),
    ]

    lines = [f"{label}: {fmt(value)}" for label, value in counters]
    peak_label = stats.get("peak_minute_label")
    if isinstance(peak_label, str) and peak_label:
        lines.append(f"Peak minute label: {peak_label}")
    return lines


def format_watchlists(stats: Dict, compact: bool = True) -> List[str]:
    entries = [
        ("Campaign watchlist", stats.get("campaign_watchlist")),
        ("Surge watch", stats.get("surge_sources")),
        ("Probability spikes", stats.get("probability_spike_sources")),
        ("Intensity watch", stats.get("intensity_watchlist")),
        ("Fan-out", stats.get("fanout_sources")),
        ("Port diversity", stats.get("port_diversity_sources")),
        ("Role counts", stats.get("role_counts")),
    ]
    lines: List[str] = []
    for label, mapping in entries:
        if compact:
            lines.append(format_compact_top(mapping, label, 3))
        else:
            lines.append(format_compact_top(mapping, label, 5))
    return lines


def format_kill_chain(stats: Dict) -> List[str]:
    lines = [
        format_compact_top(stats.get("tactic_counts"), "Tactics", 5),
        format_compact_top(stats.get("technique_counts"), "Techniques", 5),
        format_compact_top(stats.get("tactic_transitions"), "Transitions", 4),
        format_compact_top(stats.get("tactic_stage_totals"), "Stages", 5),
        format_compact_top(stats.get("kill_chain_progressions"), "Kill-chain progressions", 4),
        format_compact_top(stats.get("tactic_diversity_sources"), "Tactic diversity", 4),
    ]
    return lines


def format_network_hotspots(stats: Dict) -> List[str]:
    lines = [
        format_compact_top(stats.get("sources"), "Source IPs", 5),
        format_compact_top(stats.get("destinations"), "Destination IPs", 5),
        format_compact_top(stats.get("destination_subnets"), "Target subnets", 4),
        format_compact_top(stats.get("destination_ports"), "Destination ports", 6),
        format_compact_top(stats.get("protocols"), "Protocols", 6),
        format_compact_top(stats.get("destination_categories"), "Destination categories", 4),
    ]
    return lines


def format_distributions(stats: Dict) -> List[str]:
    buckets = stats.get("probability_buckets") or {}
    hourly = stats.get("hourly_distribution") or {}
    minute_counts = stats.get("minute_counts") or {}
    distributions = [
        format_compact_top(buckets, "Probability buckets", 6),
        format_compact_top(hourly, "Hourly alert volume", 8),
        format_compact_top(minute_counts, "Recent minute velocity", 6),
    ]
    return distributions


def analyze_probability_coverage(stats: Dict) -> List[str]:
    buckets = stats.get("probability_buckets")
    if not isinstance(buckets, dict) or not buckets:
        return ["Probability bucket telemetry unavailable."]

    parsed: List[Tuple[float, float, str, int]] = []
    invalid: List[str] = []
    for label, raw_count in buckets.items():
        parsed_range = _parse_probability_bucket(label)
        if parsed_range is None:
            invalid.append(str(label))
            continue
        try:
            count = int(raw_count)
        except (TypeError, ValueError):
            invalid.append(str(label))
            continue
        if count < 0:
            invalid.append(str(label))
            continue
        parsed.append((parsed_range[0], parsed_range[1], str(label), count))

    lines: List[str] = []
    if invalid:
        lines.append(f"⚠ Invalid bucket definitions: {', '.join(sorted(set(invalid)))}")

    if not parsed:
        if not lines:
            lines.append("Probability bucket telemetry unavailable.")
        return lines

    parsed.sort(key=lambda item: (item[0], item[1]))
    total = sum(count for _, _, _, count in parsed)
    lines.append(
        f"{len(parsed)} ranges covering {parsed[0][0]:.2f}–{parsed[-1][1]:.2f} (total {total})."
    )

    if parsed[0][0] > PROBABILITY_BUCKET_TOLERANCE:
        lines.append("⚠ Coverage does not start near 0.0 — low probabilities untracked.")
    if parsed[-1][1] < 1.0 - PROBABILITY_BUCKET_TOLERANCE:
        lines.append("⚠ Coverage stops before 1.0 — high probabilities trimmed.")

    previous_upper: Optional[float] = None
    previous_label: Optional[str] = None
    overlaps = False
    gaps = False
    for lower, upper, label, _ in parsed:
        if previous_upper is not None:
            if lower - PROBABILITY_BUCKET_TOLERANCE > previous_upper:
                lines.append(
                    f"⚠ Gap between {previous_label or 'previous bucket'} and {label}"
                    f" leaves {previous_upper:.2f}–{lower:.2f} uncovered."
                )
                gaps = True
            if lower + PROBABILITY_BUCKET_TOLERANCE < previous_upper:
                lines.append(f"⚠ Bucket {label} overlaps with an earlier range.")
                overlaps = True
        previous_upper = upper
        previous_label = label
    if not overlaps and not gaps and len(lines) == 1:
        lines.append("Probability bucket ranges appear ordered, gap-free, and non-overlapping.")

    last_prob = stats.get("last_probability")
    latest_probability: Optional[float] = None
    try:
        if last_prob is not None:
            latest_probability = float(last_prob)
    except (TypeError, ValueError):
        latest_probability = None
    if latest_probability is None:
        _, _, latest_probability = _latest_recent_alert(stats)

    if latest_probability is not None:
        match = next(
            (
                (label, count)
                for lower, upper, label, count in parsed
                if lower - PROBABILITY_BUCKET_TOLERANCE
                <= latest_probability
                <= upper + PROBABILITY_BUCKET_TOLERANCE
            ),
            None,
        )
        if match:
            label, count = match
            lines.append(
                f"Latest alert probability {latest_probability:.3f} falls in {label} ({count} events)."
            )
            if count == 0:
                lines.append(
                    f"⚠ Bucket {label} reports zero events despite the latest alert falling within it."
                )
        else:
            lines.append(
                f"⚠ Latest alert probability {latest_probability:.3f} not covered by any bucket."
            )

    return lines


def analyze_hourly_distribution(stats: Dict) -> List[str]:
    data = stats.get("hourly_distribution")
    if not isinstance(data, dict) or not data:
        return ["Hourly distribution telemetry unavailable."]

    lines: List[str] = []
    buckets: Dict[int, int] = {}
    for label, raw_count in data.items():
        try:
            hour = int(label)
        except (TypeError, ValueError):
            lines.append(f"⚠ Hour bucket {label!r} is not numeric.")
            continue
        if not 0 <= hour <= 23:
            lines.append(f"⚠ Hour bucket {label!r} lies outside expected 0–23 range.")
            continue
        try:
            count = int(raw_count)
        except (TypeError, ValueError):
            lines.append(f"⚠ Hour {hour:02d} count {raw_count!r} not an integer.")
            continue
        if count < 0:
            lines.append(f"⚠ Hour {hour:02d} reports negative alert volume ({count}).")
            continue
        buckets[hour] = count

    if not buckets:
        if not lines:
            lines.append("Hourly distribution contains no recorded alerts.")
        return lines

    sorted_hours = sorted(buckets)
    span = f"{sorted_hours[0]:02d}"
    if sorted_hours[-1] != sorted_hours[0]:
        span = f"{sorted_hours[0]:02d}–{sorted_hours[-1]:02d}"
    lines.append(
        f"{len(sorted_hours)} hour bucket(s) recorded spanning {span}."
    )

    if len(sorted_hours) > 24:
        lines.append("⚠ More than 24 hour buckets captured — retention window unexpected.")

    now_hour = datetime.now(timezone.utc).hour
    raw_last_hour = stats.get("alerts_last_hour")
    try:
        alerts_last_hour = int(raw_last_hour)
    except (TypeError, ValueError):
        alerts_last_hour = None
        if raw_last_hour not in (None, ""):
            lines.append(f"⚠ alerts_last_hour value {raw_last_hour!r} not numeric.")

    if alerts_last_hour is not None and alerts_last_hour > 0:
        current_bucket = buckets.get(now_hour)
        if current_bucket is None:
            lines.append(
                "⚠ Current hour missing from hourly_distribution despite alerts in the last hour."
            )
        elif current_bucket <= 0:
            lines.append(
                "⚠ Current hour bucket reports zero alerts while alerts_last_hour indicates activity."
            )
        else:
            lines.append(
                f"Current hour {now_hour:02d} recorded {current_bucket} alert(s) per hourly_distribution."
            )
    elif alerts_last_hour == 0:
        lines.append("No alerts recorded in the last hour per telemetry counters.")

    latest_time, _, _ = _latest_recent_alert(stats)
    if latest_time is not None:
        recent_hour = latest_time.astimezone(timezone.utc).hour
        bucket = buckets.get(recent_hour)
        if bucket is None:
            lines.append(
                "⚠ Hourly distribution missing bucket for the hour containing the most recent alert."
            )
        elif bucket <= 0:
            lines.append(
                "⚠ Hour containing the most recent alert reports zero alerts in hourly_distribution."
            )
        else:
            lines.append(
                f"Hour {recent_hour:02d} reflects the most recent alert with {bucket} recorded."
            )

    top_hours = sorted(buckets.items(), key=lambda item: item[1], reverse=True)[:3]
    if top_hours:
        formatted = ", ".join(f"{hour:02d}h:{count}" for hour, count in top_hours)
        lines.append(f"Top hourly volumes: {formatted}.")

    return lines


def analyze_model_alignment(stats: Dict) -> List[str]:
    info = stats.get("model_info")
    if not isinstance(info, dict):
        return ["⚠ Model telemetry unavailable; unable to reconcile metadata with the artifact."]

    lines: List[str] = []
    now = datetime.now(timezone.utc)

    last_trained_raw = info.get("last_trained")
    last_trained: Optional[datetime] = None
    if last_trained_raw:
        if isinstance(last_trained_raw, str):
            last_trained = _coerce_datetime(last_trained_raw)
            if last_trained is None:
                lines.append("⚠ model_info.last_trained could not be parsed as an ISO timestamp.")
            else:
                if last_trained > now + MODEL_CLOCK_SKEW_TOLERANCE:
                    skew = last_trained - now
                    lines.append(
                        f"⚠ model_info.last_trained leads the system clock by {_format_duration(skew)}; check time sync."
                    )
        else:
            lines.append("⚠ model_info.last_trained has unexpected type; telemetry writer regression suspected.")
    else:
        lines.append("⚠ model_info.last_trained missing from telemetry metadata.")

    model_timestamp: Optional[datetime] = None
    model_size: Optional[int] = None
    try:
        stat = MODEL_PATH.stat()
    except FileNotFoundError:
        lines.append(f"⚠ Model artifact missing at {MODEL_PATH}.")
    except OSError as exc:
        lines.append(f"⚠ Unable to stat model artifact: {exc}.")
    else:
        model_timestamp = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        model_size = stat.st_size
        age = now - model_timestamp
        lines.append(f"Model artifact updated {_format_duration(age)} ago.")

    if last_trained and model_timestamp:
        delta = last_trained - model_timestamp
        if delta < timedelta(0):
            delta = -delta
        if delta > MODEL_TIMESTAMP_TOLERANCE:
            lines.append(
                f"⚠ Model file timestamp differs from model_info.last_trained by {_format_duration(delta)}; metadata drift detected."
            )
        else:
            lines.append(
                f"Model metadata aligns with artifact timestamp (Δ {_format_duration(delta)})."
            )
    elif last_trained and not model_timestamp:
        lines.append("⚠ Unable to verify model_info.last_trained without model artifact metadata.")
    elif model_timestamp and not last_trained:
        lines.append("⚠ Model artifact present but last_trained metadata missing for correlation.")

    artifact_size_raw = info.get("artifact_size")
    artifact_size: Optional[int] = None
    if artifact_size_raw is not None:
        if isinstance(artifact_size_raw, bool) or not isinstance(artifact_size_raw, int):
            lines.append("⚠ model_info.artifact_size has unexpected type; telemetry reducer regression suspected.")
        elif artifact_size_raw < 0:
            lines.append("⚠ model_info.artifact_size is negative; metadata corruption suspected.")
        else:
            artifact_size = int(artifact_size_raw)
            if model_size is not None:
                if artifact_size != model_size:
                    lines.append(
                        f"⚠ model_info.artifact_size ({artifact_size}) disagrees with artifact size on disk ({model_size})."
                    )
                else:
                    lines.append(f"Model artifact size matches telemetry metadata ({artifact_size} bytes).")
            else:
                lines.append("⚠ Artifact size telemetry present but model artifact metadata unavailable for comparison.")
    elif model_timestamp is not None:
        lines.append("⚠ model_info.artifact_size missing; unable to verify artifact size against telemetry.")

    artifact_hash_raw = info.get("artifact_sha256")
    normalized_hash: Optional[str] = None
    if artifact_hash_raw:
        if isinstance(artifact_hash_raw, str):
            candidate = artifact_hash_raw.strip().lower()
            if len(candidate) != 64:
                lines.append("⚠ model_info.artifact_sha256 must be a 64-character hexadecimal digest.")
            else:
                try:
                    bytes.fromhex(candidate)
                except ValueError:
                    lines.append("⚠ model_info.artifact_sha256 is not valid hexadecimal; metadata corruption suspected.")
                else:
                    normalized_hash = candidate
        else:
            lines.append("⚠ model_info.artifact_sha256 has unexpected type; telemetry reducer regression suspected.")
    elif model_timestamp is not None:
        lines.append("⚠ model_info.artifact_sha256 missing; unable to validate artifact integrity against telemetry.")

    computed_hash: Optional[str] = None
    if normalized_hash is not None:
        if model_size is None:
            lines.append("⚠ model_info.artifact_sha256 provided but artifact metadata unavailable for comparison.")
        else:
            computed_hash = _compute_file_sha256(MODEL_PATH)
            if computed_hash is None:
                lines.append("⚠ Unable to compute model artifact hash for comparison with telemetry metadata.")
            elif computed_hash != normalized_hash:
                lines.append(
                    "⚠ model_info.artifact_sha256 does not match the computed artifact hash; investigate potential tampering."
                )
            else:
                lines.append("Model artifact hash matches telemetry metadata.")
    elif artifact_hash_raw:
        # Already reported above but ensure operators have guidance when validation could not run
        if model_size is None:
            lines.append("⚠ Unable to compare model_info.artifact_sha256 without artifact metadata.")

    age_days_raw = info.get("age_days")
    age_days: Optional[float] = None
    if age_days_raw is not None:
        try:
            age_days = float(age_days_raw)
        except (TypeError, ValueError):
            lines.append("⚠ model_info.age_days is not numeric; telemetry reducer inconsistent.")
        else:
            if age_days < 0:
                lines.append("⚠ model_info.age_days is negative; metadata corruption suspected.")
            else:
                reference = last_trained or model_timestamp
                if reference is not None:
                    computed_age = max((now - reference).total_seconds() / 86_400.0, 0.0)
                    diff_days = abs(computed_age - age_days)
                    if diff_days > MODEL_AGE_DAYS_TOLERANCE:
                        lines.append(
                            f"⚠ model_info.age_days ({age_days:.2f}d) diverges from recorded timestamps ({computed_age:.2f}d)."
                        )
                    else:
                        lines.append(
                            f"Model age telemetry ({age_days:.2f}d) matches recorded training time (Δ {diff_days:.2f}d)."
                        )
                else:
                    lines.append(f"Reported model age: {age_days:.2f}d (no timestamp available for cross-check).")
    else:
        lines.append("⚠ model_info.age_days missing; staleness tracking unavailable.")

    if not lines:
        lines.append("Model metadata appears internally consistent.")
    return lines

def summarize_recent_alignment(stats: Dict) -> List[str]:
    latest_time, latest_reason, latest_probability = _latest_recent_alert(stats)
    minute_counts = stats.get("minute_counts") if isinstance(stats.get("minute_counts"), dict) else {}
    reason_counts = stats.get("reason_counts") if isinstance(stats.get("reason_counts"), dict) else {}
    lines: List[str] = []

    if latest_time is None:
        return ["No valid recent alerts found to cross-check."]

    minute_label = (
        latest_time.astimezone(timezone.utc)
        .replace(second=0, microsecond=0)
        .strftime(MINUTE_FORMAT)
    )
    bucket_value = minute_counts.get(minute_label)
    if bucket_value is None:
        lines.append(
            f"⚠ minute_counts missing bucket for {minute_label} covering the latest alert."
        )
    else:
        try:
            numeric_bucket = int(bucket_value)
        except (TypeError, ValueError):
            lines.append(
                f"⚠ minute_counts entry for {minute_label} not numeric ({bucket_value!r})."
            )
        else:
            lines.append(
                f"{minute_label} recorded {numeric_bucket} alert(s) in minute_counts."
            )
            if numeric_bucket <= 0:
                lines.append(
                    f"⚠ minute_counts shows zero alerts for {minute_label} despite a captured alert."
                )

    reason_candidates = {
        candidate.strip()
        for candidate in (
            latest_reason,
            stats.get("last_reason"),
            stats.get("last_canonical_reason"),
        )
        if isinstance(candidate, str) and candidate.strip()
    }
    if reason_candidates:
        matched = next(
            (
                (reason, reason_counts.get(reason))
                for reason in reason_candidates
                if isinstance(reason_counts.get(reason), (int, float))
                and int(reason_counts.get(reason)) > 0
            ),
            None,
        )
        if matched:
            reason, count = matched
            lines.append(f"Reason '{reason}' tallied at {int(count)} occurrence(s).")
        else:
            lines.append(
                "⚠ Latest alert reason not reflected in reason_counts aggregates."
            )
    else:
        lines.append("Latest alert reason unavailable for reconciliation.")

    if latest_probability is not None:
        lines.append(f"Latest alert probability: {latest_probability:.3f}")

    return lines


def analyze_timeline_integrity(stats: Dict) -> List[str]:
    now = datetime.now(timezone.utc)
    lines: List[str] = []

    last_alert_dt = _coerce_datetime(stats.get("last_alert"))
    if last_alert_dt is None:
        lines.append("last_alert timestamp unavailable for timeline assessment.")
    else:
        if last_alert_dt > now + CLOCK_SKEW_TOLERANCE:
            skew = last_alert_dt - now
            lines.append(
                f"⚠ last_alert timestamp leads system clock by {_format_duration(skew)}; investigate NTP or clock drift."
            )
        else:
            age = now - last_alert_dt
            lines.append(f"Last alert recorded {_format_duration(age)} ago (within tolerance).")

    entries = stats.get("recent_alerts")
    if not isinstance(entries, list) or not entries:
        lines.append("No recent alerts to evaluate chronological ordering.")
        return lines

    misordered = 0
    future_entries = 0
    max_future_skew = timedelta(0)
    previous_timestamp: Optional[datetime] = None
    counted_entries = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        timestamp = _coerce_datetime(entry.get("time"))
        if timestamp is None:
            continue
        counted_entries += 1
        if timestamp > now + CLOCK_SKEW_TOLERANCE:
            future_entries += 1
            skew = timestamp - now
            if skew > max_future_skew:
                max_future_skew = skew
        if previous_timestamp is not None and timestamp < previous_timestamp:
            misordered += 1
        if previous_timestamp is None or timestamp >= previous_timestamp:
            previous_timestamp = timestamp

    if counted_entries == 0:
        lines.append("No timestamped entries present in recent_alerts.")
        return lines

    if future_entries:
        suffix = "y" if future_entries == 1 else "ies"
        lines.append(
            f"⚠ {future_entries} timeline entr{suffix} appear up to {_format_duration(max_future_skew)} ahead of the system clock."
        )
    if misordered:
        suffix = "y" if misordered == 1 else "ies"
        lines.append(
            f"⚠ Recent alerts not strictly chronological ({misordered} out-of-order entr{suffix})."
        )
    if not future_entries and not misordered:
        lines.append("Recent alerts appear chronological and clock-aligned within tolerance.")

    return lines


def collect_integrity_alerts(stats: Dict) -> List[str]:
    if not isinstance(stats, dict) or not stats:
        return [
            "Telemetry unavailable — run the health check (press V) to repopulate data.",
        ]

    alerts: List[str] = []
    now = datetime.now(timezone.utc)

    def flag(message: str) -> None:
        alerts.append(f"⚠ {message}")

    latest_time, latest_reason, helper_probability = _latest_recent_alert(stats)
    probability_to_check: Optional[float] = helper_probability
    try:
        last_probability = stats.get("last_probability")
        if probability_to_check is None and last_probability is not None:
            probability_to_check = float(last_probability)
    except (TypeError, ValueError):
        probability_to_check = helper_probability

    last_reason = stats.get("last_reason")
    if not isinstance(last_reason, str) or not last_reason.strip():
        last_reason = None
    else:
        last_reason = last_reason.strip()

    canonical_reason = stats.get("last_canonical_reason")
    if not isinstance(canonical_reason, str) or not canonical_reason.strip():
        canonical_reason = None
    else:
        canonical_reason = canonical_reason.strip()

    total_alerts = stats.get("total_alerts")
    total_value: Optional[int] = None
    if isinstance(total_alerts, int):
        if total_alerts < 0:
            flag("Total alerts counter reported as negative; investigate telemetry writer.")
        else:
            total_value = total_alerts
    else:
        flag("Total alerts counter missing from telemetry.")

    recent = stats.get("recent_alerts")
    if isinstance(recent, list) and len(recent) > RECENT_ALERT_MAX_ENTRIES:
        flag(
            f"recent_alerts contains {len(recent)} entries (expected ≤ {RECENT_ALERT_MAX_ENTRIES}); trim policy failing."
        )
    elif recent is not None and not isinstance(recent, list):
        flag("recent_alerts field is not a list; telemetry JSON corrupted?")

    future_alerts = 0
    max_skew = timedelta(0)
    previous_timestamp: Optional[datetime] = None
    if isinstance(recent, list):
        for entry in recent:
            if not isinstance(entry, dict):
                continue
            timestamp = _coerce_datetime(entry.get("time"))
            if timestamp is None:
                continue
            if timestamp > now + CLOCK_SKEW_TOLERANCE:
                future_alerts += 1
                skew = timestamp - now
                if skew > max_skew:
                    max_skew = skew
            if previous_timestamp is not None and timestamp < previous_timestamp:
                flag("recent_alerts timeline appears out of order; verify telemetry writer.")
            if previous_timestamp is None or timestamp >= previous_timestamp:
                previous_timestamp = timestamp
    if future_alerts:
        flag(
            f"{future_alerts} recent alert(s) are timestamped up to {_format_duration(max_skew)} ahead of the system clock."
        )

    last_alert_dt = _coerce_datetime(stats.get("last_alert"))
    if total_value and last_alert_dt is None:
        flag("Alerts recorded but last_alert timestamp missing or invalid.")
    if last_alert_dt is not None:
        age = now - last_alert_dt
        if age > timedelta(hours=1):
            flag(
                f"Last alert observed {_format_duration(age)} ago; capture pipeline may be stalled."
            )
        if last_alert_dt > now + CLOCK_SKEW_TOLERANCE:
            skew = last_alert_dt - now
            flag(
                f"last_alert timestamp is {_format_duration(skew)} ahead of system clock — check NTP."
            )

    alerts_last_hour = stats.get("alerts_last_hour")
    if isinstance(alerts_last_hour, int) and total_value is not None:
        if alerts_last_hour > total_value:
            flag("alerts_last_hour exceeds total alerts; counters diverging.")

    reason_counts = stats.get("reason_counts")
    if isinstance(reason_counts, dict) and total_value is not None:
        reason_total = sum(
            int(value)
            for value in reason_counts.values()
            if isinstance(value, (int, float))
        )
        if reason_total != total_value:
            flag(
                f"Reason aggregates ({reason_total}) diverge from total alerts ({total_value})."
            )
        reason_candidates = {
            candidate
            for candidate in (latest_reason, last_reason, canonical_reason)
            if candidate
        }
        if reason_candidates and not any(
            int(reason_counts.get(candidate, 0)) > 0
            for candidate in reason_candidates
            if isinstance(reason_counts.get(candidate), (int, float))
        ):
            flag("Latest alert reason missing from reason_counts telemetry.")

    minute_counts = stats.get("minute_counts")
    if isinstance(minute_counts, dict) and latest_time is not None:
        minute_label = (
            latest_time.astimezone(timezone.utc)
            .replace(second=0, microsecond=0)
            .strftime(MINUTE_FORMAT)
        )
        bucket_value = minute_counts.get(minute_label)
        if bucket_value is None:
            flag(
                f"minute_counts missing {minute_label} bucket corresponding to the latest alert."
            )
        else:
            try:
                numeric_bucket = int(bucket_value)
            except (TypeError, ValueError):
                flag(
                    f"minute_counts bucket {minute_label} not numeric ({bucket_value!r})."
                )
            else:
                if numeric_bucket <= 0:
                    flag(
                        f"minute_counts bucket {minute_label} reports zero despite a recent alert."
                    )

    def _check_probability(field: str, label: str) -> None:
        value = stats.get(field)
        if value is None:
            return
        try:
            number = float(value)
        except (TypeError, ValueError):
            flag(f"{label} is not numeric ({value!r}).")
            return
        if not 0.0 <= number <= 1.0:
            flag(f"{label} {number:.3f} outside [0, 1] range.")

    _check_probability("last_probability", "Last alert probability")
    _check_probability("average_probability", "Average probability")
    _check_probability("recent_probability_average", "Recent probability average")

    probability_buckets = stats.get("probability_buckets")
    if isinstance(probability_buckets, dict) and probability_buckets:
        parsed: List[Tuple[float, float, str, int]] = []
        invalid: List[str] = []
        for label, raw_count in probability_buckets.items():
            parsed_range = _parse_probability_bucket(label)
            if parsed_range is None:
                invalid.append(str(label))
                continue
            try:
                count = int(raw_count)
            except (TypeError, ValueError):
                invalid.append(str(label))
                continue
            parsed.append((parsed_range[0], parsed_range[1], str(label), count))

        if invalid:
            flag(f"Probability bucket definitions invalid: {', '.join(sorted(set(invalid)))}")

        if parsed:
            parsed.sort(key=lambda item: (item[0], item[1]))
            if parsed[0][0] > PROBABILITY_BUCKET_TOLERANCE:
                flag("Probability buckets skip the lowest probability range.")
            if parsed[-1][1] < 1.0 - PROBABILITY_BUCKET_TOLERANCE:
                flag("Probability buckets do not extend to 1.0; high-confidence data trimmed.")
            previous_upper: Optional[float] = None
            previous_label: Optional[str] = None
            for lower, upper, label, _ in parsed:
                if previous_upper is not None:
                    if lower - PROBABILITY_BUCKET_TOLERANCE > previous_upper:
                        flag(
                            f"Gap between {previous_label or 'previous bucket'} and {label} leaves"
                            f" {previous_upper:.2f}–{lower:.2f} uncovered."
                        )
                    if lower + PROBABILITY_BUCKET_TOLERANCE < previous_upper:
                        flag(f"Probability bucket {label} overlaps an earlier range.")
                previous_upper = upper
                previous_label = label

            if probability_to_check is not None:
                match = next(
                    (
                        (label, count)
                        for lower, upper, label, count in parsed
                        if lower - PROBABILITY_BUCKET_TOLERANCE
                        <= probability_to_check
                        <= upper + PROBABILITY_BUCKET_TOLERANCE
                    ),
                    None,
                )
                if match is None:
                    flag(
                        "Latest alert probability not represented in probability buckets; reducer lagging."
                    )
                else:
                    label, count = match
                    if count <= 0:
                        flag(
                            f"Probability bucket {label} reports zero events despite the latest alert falling within it."
                        )

    model_health = stats.get("model_health")
    info = stats.get("model_info") if isinstance(stats.get("model_info"), dict) else {}
    if isinstance(info, dict) and info.get("health"):
        model_health = info.get("health")
    if isinstance(model_health, str) and model_health.lower() not in {"nominal", "healthy"}:
        flag(f"Model health reports '{model_health}'.")
    if isinstance(info, dict) and info.get("refresh_recommended"):
        flag("Model refresh recommended flag is active.")

    prob_stddev = stats.get("prob_stddev")
    if prob_stddev is not None:
        try:
            std_value = float(prob_stddev)
        except (TypeError, ValueError):
            flag("Probability standard deviation not numeric.")
        else:
            if std_value < 0:
                flag("Probability standard deviation reported as negative.")

    if not alerts:
        alerts.append("Telemetry appears consistent — no anomalies detected.")

    return alerts


def format_file_freshness(entries: Sequence[Tuple[str, Path]]) -> List[str]:
    lines: List[str] = []
    now = datetime.now(timezone.utc)
    for label, path in entries:
        if not path.exists():
            lines.append(f"{label}: missing — {path}")
            continue
        try:
            stat = path.stat()
        except OSError as exc:
            lines.append(f"{label}: unable to read metadata ({exc})")
            continue
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        age = now - mtime
        lines.append(f"{label}: updated {_format_duration(age)} ago — {path}")
    if not lines:
        return ["No paths tracked yet."]
    return lines


def analyze_filesystem_hygiene(entries: Sequence[Tuple[str, Path]]) -> List[str]:
    """Summarize ownership and permissions for security-sensitive assets."""

    lines: List[str] = []
    seen: Set[Path] = set()
    allowed_uids = {0, os.getuid()}

    for label, path in entries:
        if path in seen:
            continue
        seen.add(path)
        try:
            stat_result = path.lstat()
        except FileNotFoundError:
            lines.append(f"⚠ {label}: missing — {path}")
            continue
        except OSError as exc:
            lines.append(f"⚠ {label}: unable to stat {path} ({exc})")
            continue

        permissions = stat.S_IMODE(stat_result.st_mode)
        owner = _describe_owner(stat_result.st_uid, stat_result.st_gid)
        mode_text = _format_mode(stat_result.st_mode)

        issues: List[str] = []
        if stat.S_ISLNK(stat_result.st_mode):
            issues.append("unexpected symlink")
        if permissions & stat.S_IWOTH:
            issues.append("world-writable")
        if permissions & stat.S_IWGRP:
            issues.append("group-writable")
        if stat_result.st_uid not in allowed_uids:
            issues.append(f"owned by {owner} (harden ownership)")

        if issues:
            joined = ", ".join(issues)
            lines.append(f"⚠ {label}: {joined} — {path} ({owner} {mode_text})")
        else:
            kind = "directory" if stat.S_ISDIR(stat_result.st_mode) else "file"
            lines.append(f"{label}: secure {kind} ({owner} {mode_text})")

    if not lines:
        lines.append("No filesystem targets evaluated.")

    return lines


def format_health_log_summary() -> List[str]:
    if not HEALTH_LOG.exists():
        return ["Health check log not found."]
    try:
        lines = HEALTH_LOG.read_text().splitlines()
    except OSError as exc:
        return [f"Failed to read {HEALTH_LOG}: {exc}"]
    if not lines:
        return ["Health check log is empty."]

    last_run: Optional[str] = None
    last_failure: Optional[str] = None
    for line in reversed(lines):
        if "Health check" not in line:
            continue
        if last_run is None:
            last_run = line
        if last_failure is None and "FAIL" in line.upper():
            last_failure = line
        if last_run and last_failure:
            break

    summary: List[str] = []
    summary.append(last_run or "No health check summary entries yet.")
    if last_failure and last_failure != last_run:
        summary.append(f"Last failure: {last_failure}")
    return summary


def format_health_log_tail(limit: int = 10) -> List[str]:
    if not HEALTH_LOG.exists():
        return ["Health check log not found."]
    try:
        lines = HEALTH_LOG.read_text().splitlines()
    except OSError as exc:
        return [f"Failed to read {HEALTH_LOG}: {exc}"]
    if not lines:
        return ["Health check log is empty."]
    return lines[-limit:]


def format_logs() -> List[str]:
    lines: List[str] = []
    for label, path in DEFAULT_LOGS.items():
        exists = path.exists()
        status = "OK" if exists else "missing"
        lines.append(f"{label.replace('_', ' ').title():<20} {status:>7} — {path}")
    return lines


def format_config_lines(config_path: Optional[Path], config: Dict[str, str]) -> List[str]:
    if not config:
        return ["Configuration file not found. Using defaults."]
    def as_bool(key: str) -> str:
        return "ON" if config.get(key, "0") == "1" else "OFF"

    lines = [
        f"Notifications: {as_bool('NN_IDS_NOTIFY')}",
        f"Discovery mode: {config.get('NN_IDS_DISCOVERY_MODE', 'auto')}",
        f"Packet sanitization: {as_bool('NN_IDS_SANITIZE')}",
        f"Autoblock: {as_bool('NN_IDS_AUTOBLOCK')}",
        f"Threat feed: {as_bool('NN_IDS_THREAT_FEED')}",
        f"Alert threshold: {config.get('NN_IDS_THRESHOLD', '0.5')}",
    ]
    if config_path:
        lines.append(f"Config file: {config_path}")
    return lines


def analyze_config_integrity(
    config_path: Optional[Path],
    config: Dict[str, str],
    duplicates: Sequence[str],
    malformed: Sequence[str],
) -> List[str]:
    lines: List[str] = []
    issues = False

    if config_path is None:
        locations = ", ".join(str(path) for path in CONFIG_CANDIDATES)
        lines.append("⚠ Configuration file not detected; defaults in effect.")
        lines.append(f"   Expected one of: {locations}")
        return lines

    lines.append(f"Source: {config_path}")

    for detail in malformed:
        lines.append(f"⚠ Parse issue: {detail}")
        issues = True

    for detail in duplicates:
        lines.append(f"⚠ Duplicate setting: {detail} (last value takes effect)")
        issues = True

    float_values: Dict[str, float] = {}

    for key, label in CONFIG_BOOL_KEYS.items():
        value = config.get(key)
        if value is None:
            lines.append(f"⚠ {label} ({key}) missing; defaults may weaken defenses.")
            issues = True
            continue
        if value not in {"0", "1"}:
            lines.append(f"⚠ {label} ({key}) has invalid value {value!r}; expected 0 or 1.")
            issues = True
            continue
        state = "enabled" if value == "1" else "disabled"
        lines.append(f"{label}: {state}")

    for key, (label, minimum, maximum) in CONFIG_FLOAT_FIELDS.items():
        value = config.get(key)
        if value is None:
            lines.append(f"⚠ {label} ({key}) missing; set within {minimum}–{maximum}.")
            issues = True
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            lines.append(f"⚠ {label} ({key}) not numeric ({value!r}).")
            issues = True
            continue
        if not (minimum <= number <= maximum):
            lines.append(
                f"⚠ {label} ({key}) {number:.3f} outside {minimum}–{maximum}."
            )
            issues = True
            continue
        float_values[key] = number
        lines.append(f"{label}: {number:.3f}")

    for key, (label, minimum, maximum) in CONFIG_INT_FIELDS.items():
        value = config.get(key)
        if value is None:
            lines.append(f"⚠ {label} ({key}) missing; set within {minimum}–{maximum}.")
            issues = True
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            lines.append(f"⚠ {label} ({key}) not an integer ({value!r}).")
            issues = True
            continue
        if not (minimum <= number <= maximum):
            lines.append(f"⚠ {label} ({key}) {number} outside {minimum}–{maximum}.")
            issues = True
            continue
        lines.append(f"{label}: {number}")

    mode = config.get(CONFIG_DISCOVERY_KEY)
    if mode is None:
        lines.append(
            f"⚠ Discovery mode ({CONFIG_DISCOVERY_KEY}) missing; choose {sorted(CONFIG_DISCOVERY_MODES)}."
        )
        issues = True
    else:
        normalized = mode.lower()
        if normalized not in CONFIG_DISCOVERY_MODES:
            lines.append(
                f"⚠ Discovery mode ({CONFIG_DISCOVERY_KEY}) invalid ({mode!r});"
                f" valid options: {sorted(CONFIG_DISCOVERY_MODES)}."
            )
            issues = True
        else:
            lines.append(f"Discovery mode: {normalized}")

    min_risk = float_values.get("GA_PROC_MIN_RISK")
    threshold = float_values.get("GA_PROC_THRESHOLD")
    if min_risk is not None and threshold is not None and min_risk < threshold:
        lines.append(
            "⚠ GA_PROC_MIN_RISK below GA_PROC_THRESHOLD; process alerts may be skipped."
        )
        issues = True

    if not issues:
        lines.append("Configuration settings validated successfully.")

    return lines


def build_views() -> List[Tuple[str, List[Tuple[str, Sequence]]]]:
    stats = load_json(ALERT_STATS)
    config_path, config, config_duplicates, config_malformed = detect_config_with_diagnostics()
    services = gather_service_lines()
    enablement = gather_enablement_lines()
    summary = format_summary(stats)
    model = format_model_health(stats)
    adversarial = format_adversarial(stats)
    watch_compact = format_watchlists(stats, compact=True)
    watch_detailed = format_watchlists(stats, compact=False)
    kill_chain = format_kill_chain(stats)
    hotspots = format_network_hotspots(stats)
    distributions = format_distributions(stats)
    recent_alerts = format_recent_alerts(stats)
    logs = format_logs()
    operational_counters = format_operational_counters(stats)
    health_summary = format_health_log_summary()
    health_tail = format_health_log_tail()
    integrity_alerts = collect_integrity_alerts(stats)
    probability_coverage = analyze_probability_coverage(stats)
    hourly_coverage = analyze_hourly_distribution(stats)
    model_alignment = analyze_model_alignment(stats)
    recent_alignment = summarize_recent_alignment(stats)
    timeline_integrity = analyze_timeline_integrity(stats)
    freshness = format_file_freshness(
        [
            ("Alert telemetry", ALERT_STATS),
            ("IDS model", MODEL_PATH),
            ("Health log", HEALTH_LOG),
        ]
    )
    filesystem_entries: List[Tuple[str, Path]] = [
        ("Telemetry directory", ALERT_STATS.parent),
        ("Alert telemetry", ALERT_STATS),
        ("Model directory", MODEL_PATH.parent),
        ("Model artifact", MODEL_PATH),
        ("Health log directory", HEALTH_LOG.parent),
        ("Health log", HEALTH_LOG),
    ]
    if config_path:
        filesystem_entries.append(("Config directory", config_path.parent))
        filesystem_entries.append(("Configuration file", config_path))
    else:
        for candidate in CONFIG_CANDIDATES:
            filesystem_entries.append(("Configuration candidate", candidate))
    filesystem_hygiene = analyze_filesystem_hygiene(filesystem_entries)
    config_integrity = analyze_config_integrity(
        config_path, config, config_duplicates, config_malformed
    )

    summary_view = [
        ("Service Status", services),
        ("Key Settings", format_config_lines(config_path, config)),
        ("Alert Summary", summary),
        ("Model Health", model),
        ("Adversarial Snapshot", adversarial),
        ("Priority Watchlists", watch_compact),
    ]

    analytics_view = [
        ("Network Hotspots", hotspots),
        ("Kill Chain Insights", kill_chain),
        ("Advanced Watchlists", watch_detailed),
        ("Alert Distributions", distributions),
    ]

    timeline_view = [
        ("Recent Alerts", recent_alerts),
        ("Alert History & Trends", [
            format_compact_top(stats.get("recent_alert_history", {}), "Recent history", 6)
            if isinstance(stats.get("recent_alert_history"), dict)
            else "Recent history: see alert_stats.json",
            format_compact_top(stats.get("minute_counts"), "Minute activity", 6),
            f"EWMA probability: {_format_number(stats.get('global_ewma_probability'))}",
            f"Recent avg probability: {_format_number(stats.get('recent_probability_average'))}",
            f"Probability stddev: {_format_number(stats.get('prob_stddev'))}",
        ]),
        ("Logs & Reports", logs),
    ]

    operations_view = [
        ("Playbooks", [
            "Press ? to open the action palette for quick controls.",
            "Use Toggle actions to update nn_ids.conf without leaving the dashboard.",
            "Run discovery, retraining, sanitization, and incident-response directly from here.",
        ]),
        ("Incident Insights", [
            format_compact_top(stats.get("incident_keywords"), "Top keywords", 6),
            format_compact_top(stats.get("incident_tactics"), "Incident tactics", 4),
            format_compact_top(stats.get("incident_stages"), "Incident stages", 4),
            f"Incident report: {'available' if INCIDENT_REPORT.exists() else 'pending'}",
        ]),
        ("System Health", [
            format_compact_top(stats.get("service_health"), "Health counters", 4),
            format_compact_top(stats.get("model_refresh_reasons"), "Refresh reasons", 4),
            format_compact_top(stats.get("resource_alerts"), "Resource alerts", 4),
            format_compact_top(stats.get("syscall_alerts"), "Syscall signals", 4),
        ]),
    ]

    maintenance_view = [
        ("Operational Counters", operational_counters),
        ("Health Check Summary", health_summary),
        ("Recent Health Log Entries", health_tail),
        (
            "Maintenance Tips",
            [
                "Press V to run a health check without restarting services.",
                "Press J to inspect the full health check log.",
                "Press 0 to open raw alert telemetry for deep inspection.",
                "Review Configuration Integrity under Resilience after editing nn_ids.conf.",
                "Review Unit Enablement under Resilience to confirm services auto-start.",
                "Use [?] for additional maintenance automation shortcuts.",
            ],
        ),
    ]

    return [
        ("Summary", summary_view),
        ("Analytics", analytics_view),
        ("Timeline", timeline_view),
        ("Operations", operations_view),
        ("Maintenance", maintenance_view),
        (
            "Resilience",
            [
                ("Telemetry Integrity", integrity_alerts),
                ("Timeline Integrity", timeline_integrity),
                ("Probability Coverage", probability_coverage),
                ("Hourly Coverage", hourly_coverage),
                ("Model Alignment", model_alignment),
                ("Recent Alert Alignment", recent_alignment),
                ("Unit Enablement", enablement),
                ("File Freshness", freshness),
                ("Configuration Integrity", config_integrity),
                ("Filesystem Hygiene", filesystem_hygiene),
                (
                    "Mitigation Guidance",
                    [
                        "Run the health check (V) if telemetry anomalies persist.",
                        "Use the action palette (?) to restart services after addressing issues.",
                        "Enable any disabled units so IDS services recover automatically.",
                        "Review the health log (J) for full failure context.",
                    ],
                ),
            ],
        ),
    ]


def render_section(
    stdscr: "curses._CursesWindow",
    y: int,
    max_y: int,
    max_x: int,
    title: str,
    lines: Sequence,
) -> int:
    if y >= max_y - 2:
        return y
    title_text = f"[ {title} ]"
    attr = curses.A_BOLD
    if curses.has_colors():
        attr |= curses.color_pair(COLOR_TITLE)
    stdscr.addnstr(y, 0, title_text[: max_x - 1], max_x - 1, attr)
    y += 1

    for item in lines:
        if y >= max_y - 2:
            break
        text = ""
        color = 0
        if isinstance(item, tuple):
            text, color = item
        else:
            text = str(item)
        wrapped = textwrap.wrap(text, width=max_x - 2) or [""]
        for segment in wrapped:
            if y >= max_y - 2:
                break
            if color and curses.has_colors():
                stdscr.addnstr(y, 1, segment[: max_x - 2], max_x - 2, curses.color_pair(color))
            else:
                stdscr.addnstr(y, 1, segment[: max_x - 2], max_x - 2)
            y += 1
    if y < max_y - 2:
        y += 1
    return y


def open_external(stdscr: "curses._CursesWindow", command: Sequence[str]) -> None:
    curses.def_prog_mode()
    curses.endwin()
    try:
        subprocess.run(command, check=False)
    finally:
        curses.reset_prog_mode()
        curses.curs_set(0)
        stdscr.clear()


def open_log(stdscr: "curses._CursesWindow", path: Path) -> str:
    if not path.exists():
        return f"Log not found: {path}"
    viewer = shutil.which("less")
    if viewer:
        open_external(stdscr, [viewer, "-R", str(path)])
    else:
        curses.def_prog_mode()
        curses.endwin()
        try:
            print(f"=== {path} ===")
            print(path.read_text(errors="replace"))
            input("\nPress Enter to return to the dashboard...")
        finally:
            curses.reset_prog_mode()
            curses.curs_set(0)
            stdscr.clear()
    return f"Displayed {path}"


def open_config(stdscr: "curses._CursesWindow") -> str:
    path = resolve_config_path()
    if not path.exists():
        return f"Configuration file not found: {path}"
    return open_log(stdscr, path)


def show_actions_palette(
    stdscr: "curses._CursesWindow", actions: "OrderedDict[str, Tuple[str, Callable[[], str]]]"
) -> Optional[str]:
    max_y, max_x = stdscr.getmaxyx()
    lines = [f"{key.upper()} — {label}" for key, (label, _) in actions.items()]
    if not lines:
        return None
    width = min(max(len(line) for line in lines) + 6, max_x - 4)
    height = min(len(lines) + 4, max_y - 4)
    start_y = max((max_y - height) // 2, 0)
    start_x = max((max_x - width) // 2, 0)
    window = curses.newwin(height, width, start_y, start_x)
    window.box()
    title = " Actions "
    window.addnstr(0, max(1, (width - len(title)) // 2), title[: width - 2], width - 2, curses.A_BOLD)
    for idx, line in enumerate(lines[: height - 4]):
        window.addnstr(2 + idx, 2, line[: width - 4], width - 4)
    window.addnstr(height - 2, 2, "Select key or press Esc", width - 4, curses.A_DIM)
    window.refresh()
    window.keypad(True)
    while True:
        key = window.getch()
        if key in (-1, 27, ord("q"), ord("Q")):
            window.clear()
            window.refresh()
            del window
            return None
        if key == curses.KEY_RESIZE:
            window.clear()
            window.refresh()
            del window
            return None
        if 0 <= key < 256:
            ch = chr(key).lower()
            if ch in actions:
                window.clear()
                window.refresh()
                del window
                return ch


def launch_ids_menu(stdscr: "curses._CursesWindow") -> str:
    script = find_script("ids_menu.sh")
    if not script:
        return "Unable to locate ids_menu.sh"
    open_external(stdscr, [script])
    return "Returned from IDS control menu"


def launch_incident_report(stdscr: "curses._CursesWindow") -> str:
    if INCIDENT_REPORT.exists():
        return open_log(stdscr, INCIDENT_REPORT)
    return "Incident report not generated yet"


def main(stdscr: "curses._CursesWindow") -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(1000)
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(COLOR_SUCCESS, curses.COLOR_GREEN, -1)
        curses.init_pair(COLOR_ERROR, curses.COLOR_RED, -1)
        curses.init_pair(COLOR_WARN, curses.COLOR_YELLOW, -1)
        curses.init_pair(COLOR_TITLE, curses.COLOR_CYAN, -1)

    view_index = 0
    status_message = ""

    actions = OrderedDict(
        [
            ("a", ("View IDS alerts log", lambda: open_log(stdscr, DEFAULT_LOGS["alerts"]))),
            ("p", ("View process monitor log", lambda: open_log(stdscr, DEFAULT_LOGS["process"]))),
            ("g", ("View GA Tech process log", lambda: open_log(stdscr, DEFAULT_LOGS["ga_process"]))),
            ("s", ("View GA Tech syscall log", lambda: open_log(stdscr, DEFAULT_LOGS["ga_syscall"]))),
            ("t", ("View threat feed log", lambda: open_log(stdscr, DEFAULT_LOGS["threat_feed"]))),
            ("j", ("View health check log", lambda: open_log(stdscr, HEALTH_LOG))),
            ("0", ("View raw alert telemetry", lambda: open_log(stdscr, ALERT_STATS))),
            ("l", ("View incident analytics log", lambda: open_log(stdscr, DEFAULT_LOGS["incident"]))),
            ("c", ("Open nn_ids.conf", lambda: open_config(stdscr))),
            ("n", ("Toggle notifications", lambda: toggle_config_bool("NN_IDS_NOTIFY"))),
            ("y", ("Cycle discovery mode", cycle_discovery_mode)),
            ("z", ("Toggle packet sanitization", lambda: toggle_config_bool("NN_IDS_SANITIZE"))),
            ("b", ("Toggle automatic blocking", lambda: toggle_config_bool("NN_IDS_AUTOBLOCK"))),
            ("f", ("Toggle threat feed", lambda: toggle_config_bool("NN_IDS_THREAT_FEED"))),
            ("h", ("Set alert threshold", lambda: set_threshold(stdscr))),
            ("d", ("Run network discovery", lambda: run_script_action(stdscr, "network_discovery.sh"))),
            ("v", ("Run health check", lambda: run_healthcheck(stdscr))),
            ("x", ("Trigger IDS retrain", lambda: call_systemctl("nn_ids_retrain.service"))),
            ("u", ("Run dataset sanitization", lambda: call_systemctl("nn_ids_sanitize.service"))),
            ("k", ("Update threat feed", lambda: call_systemctl("threat_feed_blocklist.service"))),
            ("o", ("Generate incident response", lambda: run_script_action(stdscr, "nn_ids_incident_response.py", python=True))),
            ("w", ("Run GA Tech process scan", lambda: run_script_action(stdscr, "nn_process_gt.py", ["--scan", "--verbose"], python=True))),
            ("e", ("Refresh GA process baseline", lambda: run_script_action(stdscr, "nn_process_gt.py", ["--refresh-baseline"], python=True))),
            ("m", ("Open IDS control menu", lambda: launch_ids_menu(stdscr))),
            ("i", ("View incident response report", lambda: launch_incident_report(stdscr))),
            ("r", ("Refresh dashboard", lambda: "Refreshed")),
        ]
    )

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        views = build_views()
        view_index = max(0, min(view_index, len(views) - 1))
        view_name, sections = views[view_index]

        header = f"Kali Neural IDS Dashboard — {view_name} view (press 1-{len(views)} or Tab to switch)"
        stdscr.addnstr(0, 0, header[: max_x - 1], max_x - 1, curses.A_BOLD)
        y = 2
        for title, lines in sections:
            y = render_section(stdscr, y, max_y, max_x, title, lines)
            if y >= max_y - 3:
                break

        if status_message:
            stdscr.addnstr(
                max_y - 2,
                0,
                status_message[: max_x - 1].ljust(max_x - 1),
                max_x - 1,
                curses.A_REVERSE,
            )
        hint = "[Tab] Switch view  [?] Actions  [V] Health check  [J] Health log  [R] Refresh  [Q] Quit"
        stdscr.addnstr(
            max_y - 1,
            0,
            hint.ljust(max_x - 1),
            max_x - 1,
            curses.A_REVERSE,
        )
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == -1:
            continue
        if ch in (ord("q"), ord("Q")):
            break
        if ch == curses.KEY_TAB:
            view_index = (view_index + 1) % len(views)
            status_message = f"Switched to {views[view_index][0]} view"
            continue
        if ord("1") <= ch <= ord("9"):
            numeric = ch - ord("1")
            if 0 <= numeric < len(views):
                view_index = numeric
                status_message = f"Switched to {views[view_index][0]} view"
            continue
        if ch == ord("?"):
            selection = show_actions_palette(stdscr, actions)
            if not selection:
                status_message = "Action palette closed"
                continue
            key = selection
        else:
            key = chr(ch).lower()
        if key in actions:
            label, action = actions[key]
            try:
                result = action()
            except Exception as exc:  # pragma: no cover - defensive
                result = f"{label} failed: {exc}"
            if isinstance(result, str):
                status_message = result
            else:
                status_message = label
        else:
            status_message = f"Unmapped key: {repr(chr(ch))}"


if __name__ == "__main__":
    curses.wrapper(main)
