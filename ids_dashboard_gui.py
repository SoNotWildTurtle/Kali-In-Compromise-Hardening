#!/usr/bin/env python3
"""Interactive curses dashboard for Kali Neural IDS analytics.

This utility aggregates metrics from ``/var/lib/nn_ids/alert_stats.json`` and
related log files to present an at-a-glance status board for operators.  It is
safe to run on systems where the IDS has not generated data yet; sections will
note when information is unavailable.
"""
from __future__ import annotations

import curses
import json
import shutil
import subprocess
import textwrap
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

ALERT_STATS = Path("/var/lib/nn_ids/alert_stats.json")
CONFIG_CANDIDATES = [
    Path("/etc/nn_ids.conf"),
    Path(__file__).resolve().parent / "nn_ids.conf",
]
INCIDENT_REPORT = Path("/var/log/nn_ids/incident_response_report.md")
DEFAULT_LOGS: Dict[str, Path] = {
    "alerts": Path("/var/log/nn_ids_alerts.log"),
    "process": Path("/var/log/process_monitor_alerts.log"),
    "ga_process": Path("/var/log/ga_tech_proc_alerts.log"),
    "ga_syscall": Path("/var/log/ga_tech_sys_alerts.log"),
    "threat_feed": Path("/var/log/threat_feed_blocklist.log"),
    "resource": Path("/var/log/nn_ids_resource_monitor.log"),
    "network_in": Path("/var/log/inbound_traffic.log"),
    "network_out": Path("/var/log/outbound_traffic.log"),
    "anti_wipe": Path("/var/log/anti_wipe_monitor.log"),
    "autoblock": Path("/var/log/nn_ids_autoblock.log"),
    "incident": INCIDENT_REPORT,
}

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

CONFIG_BOOL_KEYS = {
    "NN_IDS_NOTIFY": "Notifications",
    "NN_IDS_SANITIZE": "Packet sanitization",
    "NN_IDS_AUTOBLOCK": "Automatic IP blocking",
    "NN_IDS_THREAT_FEED": "Threat feed updates",
}

DISCOVERY_SEQUENCE = ["auto", "manual", "notify", "none"]


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


def detect_config() -> Tuple[Optional[Path], Dict[str, str]]:
    for candidate in CONFIG_CANDIDATES:
        try:
            if candidate.exists():
                data: Dict[str, str] = {}
                for line in candidate.read_text().splitlines():
                    if not line or line.strip().startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    data[key.strip()] = value.strip()
                return candidate, data
        except OSError:
            continue
    return None, {}


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


def _parse_time(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone()
        return local.strftime("%Y-%m-%d %H:%M:%S %Z")
    except ValueError:
        return value


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


def build_views() -> List[Tuple[str, List[Tuple[str, Sequence]]]]:
    stats = load_json(ALERT_STATS)
    config_path, config = detect_config()
    services = gather_service_lines()
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

    return [
        ("Summary", summary_view),
        ("Analytics", analytics_view),
        ("Timeline", timeline_view),
        ("Operations", operations_view),
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
            ("l", ("View incident analytics log", lambda: open_log(stdscr, DEFAULT_LOGS["incident"]))),
            ("c", ("Open nn_ids.conf", lambda: open_config(stdscr))),
            ("n", ("Toggle notifications", lambda: toggle_config_bool("NN_IDS_NOTIFY"))),
            ("y", ("Cycle discovery mode", cycle_discovery_mode)),
            ("z", ("Toggle packet sanitization", lambda: toggle_config_bool("NN_IDS_SANITIZE"))),
            ("b", ("Toggle automatic blocking", lambda: toggle_config_bool("NN_IDS_AUTOBLOCK"))),
            ("f", ("Toggle threat feed", lambda: toggle_config_bool("NN_IDS_THREAT_FEED"))),
            ("h", ("Set alert threshold", lambda: set_threshold(stdscr))),
            ("d", ("Run network discovery", lambda: run_script_action(stdscr, "network_discovery.sh"))),
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
        hint = "[Tab] Switch view  [?] Actions  [R] Refresh  [Q] Quit"
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
        if ch in (ord("1"), ord("2"), ord("3"), ord("4")):
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
