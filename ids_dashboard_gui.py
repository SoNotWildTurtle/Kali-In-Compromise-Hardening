#!/usr/bin/env python3
"""Interactive curses dashboard for Kali Neural IDS analytics.

This utility aggregates metrics from ``/var/lib/nn_ids/alert_stats.json`` and
related log files to present an at-a-glance status board for operators.  It is
safe to run on systems where the IDS has not generated data yet; sections will
note when information is unavailable.
"""
from __future__ import annotations

import curses
import fnmatch
import hashlib
import ipaddress
import json
import os
import pwd
import grp
import shutil
import stat
import subprocess
import tarfile
import textwrap
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple, Set
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ALERT_STATS = Path("/var/lib/nn_ids/alert_stats.json")
MODEL_PATH = Path("/opt/nnids/ids_model.pkl")
CONFIG_CANDIDATES = [
    Path("/etc/nn_ids.conf"),
    Path("/opt/nnids/nn_ids.conf"),
    Path(__file__).resolve().parent / "nn_ids.conf",
]
INCIDENT_REPORT = Path("/var/log/nn_ids/incident_response_report.md")
HEALTH_LOG = Path("/var/log/nn_ids_health.log")
THREAT_FEED_STATE = Path("/var/lib/nn_ids/threat_feed_state.json")
THREAT_FEED_STALE_THRESHOLD = timedelta(days=2)
THREAT_FEED_CLOCK_SKEW = timedelta(minutes=5)
THREAT_FEED_DEFAULT_ENDPOINTS: Sequence[str] = [
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
]
THREAT_FEED_ENDPOINT_KEY = "NN_IDS_THREAT_FEED_ENDPOINTS"
THREAT_FEED_PROBE_TIMEOUT = 5.0
THREAT_FEED_PROBE_TTL = timedelta(minutes=5)
THREAT_FEED_USER_AGENT = "nn-ids-dashboard/1.0"
AUTOBLOCK_STATE = Path("/var/lib/nn_ids/autoblock_state.json")
AUTOBLOCK_STALE_THRESHOLD = timedelta(minutes=15)
AUTOBLOCK_CLOCK_SKEW = timedelta(minutes=5)
AUTOBLOCK_BLOCK_DURATION = timedelta(hours=24)
AUTOBLOCK_BLOCK_GRACE = timedelta(minutes=15)
AUTOBLOCK_THRESHOLD = 5
PROCESS_MONITOR_BASELINE = Path("/var/lib/process_monitor/baseline.json")
PROCESS_MONITOR_ALERT_LOG = Path("/var/log/process_monitor_alerts.log")
PROCESS_MONITOR_ACTIVITY_LOG = Path("/opt/nnids/process_log.csv")
PROCESS_MONITOR_STALE_THRESHOLD = timedelta(minutes=15)
PROCESS_MONITOR_CLOCK_SKEW = timedelta(minutes=5)
PROCESS_MONITOR_MAX_PROCESSES = 8192
PROCESS_MONITOR_MAX_SERVICES = 2048
PORT_MONITOR_BASELINE = Path("/var/lib/port_monitor/baseline.json")
PORT_MONITOR_ALERT_LOG = Path("/var/log/port_monitor_alerts.log")
PORT_MONITOR_STALE_THRESHOLD = timedelta(minutes=15)
PORT_MONITOR_CLOCK_SKEW = timedelta(minutes=5)
PORT_MONITOR_MAX_PORTS = 4096
RESOURCE_MONITOR_LOG = Path("/var/log/nn_ids_resource.log")
RESOURCE_MONITOR_STALE_THRESHOLD = timedelta(minutes=15)
RESOURCE_MONITOR_CLOCK_SKEW = timedelta(minutes=5)
RESOURCE_MONITOR_TIMER_INTERVAL = timedelta(minutes=5)
RESOURCE_MONITOR_TIMER_GRACE = timedelta(minutes=2)
RESOURCE_MONITOR_SPIKE_WINDOW = timedelta(hours=1)
RESOURCE_MONITOR_SPIKE_ALERT_COUNT = 3
RESOURCE_MONITOR_SERVICE = "nn_ids_resource_monitor.service"
RESOURCE_MONITOR_TIMER = "nn_ids_resource_monitor.timer"
NETWORK_IO_RSYSLOG_CONF = Path("/etc/rsyslog.d/20-iptables.conf")
NETWORK_IO_LOGROTATE_CONF = Path("/etc/logrotate.d/network_io")
NETWORK_IO_SERVICE = "network_io_monitor.service"
NETWORK_IO_CLOCK_SKEW = timedelta(minutes=5)
NETWORK_IO_STALE_THRESHOLD = timedelta(days=7)
NETWORK_IO_LOGS: Sequence[Tuple[str, Path, str]] = (
    ("Inbound IPv4", Path("/var/log/inbound.log"), "INBOUND: "),
    ("Outbound IPv4", Path("/var/log/outbound.log"), "OUTBOUND: "),
    ("Inbound IPv6", Path("/var/log/inbound6.log"), "INBOUND6: "),
    ("Outbound IPv6", Path("/var/log/outbound6.log"), "OUTBOUND6: "),
)
INTERNET_ACCESS_LOG = Path("/var/log/internet_access.log")
INTERNET_ACCESS_SERVICE = "internet_access_monitor.service"
INTERNET_ACCESS_TIMER = "internet_access_monitor.timer"
INTERNET_ACCESS_STALE_THRESHOLD = timedelta(minutes=15)
INTERNET_ACCESS_CLOCK_SKEW = timedelta(minutes=5)
INTERNET_ACCESS_TIMER_INTERVAL = timedelta(minutes=5)
INTERNET_ACCESS_TIMER_GRACE = timedelta(minutes=2)
INTERNET_ACCESS_SUCCESS_MARKERS: Sequence[str] = (
    "internet access verified",
    "internet access restored",
)
ANTI_WIPE_LOG = Path("/var/log/anti_wipe.log")
ANTI_WIPE_SERVICE = "anti_wipe_monitor.service"
ANTI_WIPE_SCRIPT = Path("/usr/local/bin/anti_wipe_monitor.sh")
ALERT_REPORT_LOG = Path("/var/log/nn_ids_report.log")
ALERT_REPORT_STATE = Path("/var/lib/nn_ids/report_state.json")
ALERT_REPORT_SOURCE_LOG = Path("/var/log/nn_ids_alerts.log")
ALERT_REPORT_SERVICE = "nn_ids_report.service"
ALERT_REPORT_TIMER = "nn_ids_report.timer"
ALERT_REPORT_STALE_THRESHOLD = timedelta(hours=2)
ALERT_REPORT_CLOCK_SKEW = timedelta(minutes=5)
ALERT_REPORT_TIMER_INTERVAL = timedelta(hours=1)
ALERT_REPORT_TIMER_GRACE = timedelta(minutes=10)
TIMEDATECTL_PATH = shutil.which("timedatectl")
CHRONYC_PATH = shutil.which("chronyc")
TIMESYNCD_CONFIG = Path("/etc/systemd/timesyncd.conf")
TIME_SYNC_SERVICES: Sequence[Tuple[str, str]] = (
    ("systemd-timesyncd.service", "systemd time synchronization"),
    ("chronyd.service", "Chrony time synchronization"),
    ("ntpd.service", "NTP daemon"),
)
TIME_SYNC_OFFSET_THRESHOLD = timedelta(milliseconds=250)
TIME_SYNC_STALE_THRESHOLD = timedelta(hours=6)
TIME_SYNC_CLOCK_SKEW = timedelta(minutes=5)
TIME_SYNC_STRATUM_MAX = 10
TIME_SYNC_UPDATE_MAX = timedelta(hours=1)
SSH_ACCESS_SCRIPT = Path("/usr/local/bin/ssh_access_control.sh")
SSH_WHITELIST_PATH = Path("/etc/ssh_whitelist.conf")
SSH_BLACKLIST_PATH = Path("/etc/ssh_blacklist.conf")
SSH_WHITELIST_FALLBACKS: Sequence[Path] = [
    Path("/usr/local/etc/ssh_whitelist.conf"),
    Path(__file__).resolve().parent / "ssh_whitelist.conf",
]
SSH_BLACKLIST_FALLBACKS: Sequence[Path] = [
    Path("/usr/local/etc/ssh_blacklist.conf"),
    Path(__file__).resolve().parent / "ssh_blacklist.conf",
]
SSH_CHAIN_NAME = "SSH_ACCESS"
IPTABLES_PATH = shutil.which("iptables")
DEFAULT_LOGS: Dict[str, Path] = {
    "alerts": ALERT_REPORT_SOURCE_LOG,
    "process": PROCESS_MONITOR_ALERT_LOG,
    "port_monitor": PORT_MONITOR_ALERT_LOG,
    "ga_process": Path("/var/log/ga_tech_proc_alerts.log"),
    "ga_syscall": Path("/var/log/ga_tech_sys_alerts.log"),
    "threat_feed": Path("/var/log/threat_feed_blocklist.log"),
    "resource": RESOURCE_MONITOR_LOG,
    "health": HEALTH_LOG,
    "network_in": NETWORK_IO_LOGS[0][1],
    "network_out": NETWORK_IO_LOGS[1][1],
    "network_in6": NETWORK_IO_LOGS[2][1],
    "network_out6": NETWORK_IO_LOGS[3][1],
    "internet_access": INTERNET_ACCESS_LOG,
    "anti_wipe": ANTI_WIPE_LOG,
    "autoblock": Path("/var/log/nn_ids_autoblock.log"),
    "incident": INCIDENT_REPORT,
    "ssh_whitelist": SSH_WHITELIST_PATH,
    "ssh_blacklist": SSH_BLACKLIST_PATH,
    "alert_report": ALERT_REPORT_LOG,
}

_THREAT_FEED_PROBE_CACHE: Dict[str, Tuple[datetime, bool, str]] = {}

LOGROTATE_SAMPLE = Path(__file__).resolve().parent / "nn_ids_logrotate"
LOGROTATE_CANDIDATES: List[Path] = [
    Path("/etc/logrotate.d/nn_ids"),
    Path("/etc/logrotate.d/nn-ids"),
    Path("/etc/logrotate.d/nn_ids_health"),
    LOGROTATE_SAMPLE,
]
LOGROTATE_TARGETS: List[Path] = [
    ALERT_REPORT_SOURCE_LOG,
    Path("/var/log/nn_ids_health.log"),
    ALERT_REPORT_LOG,
    Path("/var/log/nn_ids_train.log"),
    PROCESS_MONITOR_ALERT_LOG,
    PORT_MONITOR_ALERT_LOG,
    RESOURCE_MONITOR_LOG,
]
LOGROTATE_STATE_CANDIDATES: List[Path] = [
    Path("/var/lib/logrotate/status"),
    Path("/var/lib/logrotate/status-uuid"),
]
LOGROTATE_STATE_TIME_FORMATS: Sequence[str] = (
    "%Y-%m-%d-%H:%M:%S",
    "%Y-%m-%d-%H:%M",
    "%Y-%m-%d",
)
LOGROTATE_ROTATION_STALE = timedelta(days=2)
LOGROTATE_STATE_CLOCK_SKEW = timedelta(minutes=5)
SYSTEMD_TIMESTAMP_FORMATS: Sequence[str] = (
    "%a %Y-%m-%d %H:%M:%S %Z",
    "%a %Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S %Z",
    "%Y-%m-%d %H:%M:%S %z",
)
LOGROTATE_TIMER_MAX_INTERVAL = timedelta(days=2)
LOGROTATE_TIMER_GRACE = timedelta(hours=6)
SECURE_LOG_GROUPS = {"adm", "root"}
LOGROTATE_SECURE_USER = "root"
LOGROTATE_REQUIRED_DIRECTIVES = {
    "daily",
    "missingok",
    "notifempty",
    "compress",
    "delaycompress",
}
LOGROTATE_TIMER_UNIT = "logrotate.timer"
LOGROTATE_SERVICE_UNIT = "logrotate.service"
LOGROTATE_CRON_PATH = Path("/etc/cron.daily/logrotate")
MEMINFO_PATH = Path("/proc/meminfo")
LOADAVG_PATH = Path("/proc/loadavg")
CPU_RUN_QUEUE_MAX_PER_CPU = 1.5
SNAPSHOT_CANDIDATES: List[Path] = [
    Path("/var/backups/nnids"),
    Path("/opt/nnids/snapshots"),
    Path("/opt/nnids/backups"),
]
SNAPSHOT_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
SNAPSHOT_STALE_THRESHOLD = timedelta(days=7)
SNAPSHOT_CLOCK_SKEW = timedelta(minutes=10)
SNAPSHOT_VALIDATION_LIMIT = 3
SNAPSHOT_DATASET_ARCHIVE = "datasets.tar.gz"
SNAPSHOT_DATASET_TOP_LEVEL = "datasets"
SNAPSHOT_ARTIFACTS: Sequence[Tuple[str, str, str]] = (
    ("ids_model.pkl", "model.sha256", "Model artifact"),
    (SNAPSHOT_DATASET_ARCHIVE, "datasets.sha256", "Dataset archive"),
)


@dataclass(frozen=True)
class DiskUsageThreshold:
    label: str
    candidates: Tuple[Path, ...]
    min_free_bytes: int
    min_free_percent: float


@dataclass(frozen=True)
class InodeUsageThreshold:
    label: str
    candidates: Tuple[Path, ...]
    min_free_inodes: int
    min_free_percent: float


@dataclass(frozen=True)
class MemoryCapacityThreshold:
    label: str
    min_available_bytes: int
    min_available_percent: float
    min_swap_free_bytes: int
    min_swap_percent: float


@dataclass(frozen=True)
class CpuLoadThreshold:
    label: str
    max_per_cpu: float


DISK_USAGE_THRESHOLDS: Sequence[DiskUsageThreshold] = (
    DiskUsageThreshold("Root filesystem", (Path("/"),), 5 * 1024**3, 0.10),
    DiskUsageThreshold("Log storage", (Path("/var/log"),), 2 * 1024**3, 0.15),
    DiskUsageThreshold(
        "IDS installation",
        (Path("/opt/nnids"),),
        2 * 1024**3,
        0.10,
    ),
    DiskUsageThreshold(
        "Snapshot storage",
        tuple(SNAPSHOT_CANDIDATES),
        5 * 1024**3,
        0.15,
    ),
)


INODE_USAGE_THRESHOLDS: Sequence[InodeUsageThreshold] = (
    InodeUsageThreshold("Root filesystem", (Path("/"),), 20_000, 0.05),
    InodeUsageThreshold(
        "Log storage",
        (Path("/var/log"),),
        10_000,
        0.05,
    ),
    InodeUsageThreshold(
        "IDS installation",
        (Path("/opt/nnids"),),
        5_000,
        0.05,
    ),
    InodeUsageThreshold(
        "Snapshot storage",
        tuple(SNAPSHOT_CANDIDATES),
        5_000,
        0.05,
    ),
)


MEMORY_CAPACITY_THRESHOLDS: Sequence[MemoryCapacityThreshold] = (
    MemoryCapacityThreshold(
        "System memory",
        2 * 1024**3,
        0.15,
        512 * 1024**2,
        0.20,
    ),
)

CPU_LOAD_THRESHOLDS: Sequence[CpuLoadThreshold] = (
    CpuLoadThreshold("1-minute", 0.90),
    CpuLoadThreshold("5-minute", 0.80),
    CpuLoadThreshold("15-minute", 0.70),
)
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
    (RESOURCE_MONITOR_SERVICE, "Resource monitor service"),
    (RESOURCE_MONITOR_TIMER, "Resource monitor timer"),
    (INTERNET_ACCESS_SERVICE, "Internet access monitor service"),
    (INTERNET_ACCESS_TIMER, "Internet access monitor timer"),
    (ALERT_REPORT_SERVICE, "Alert report service"),
    (ALERT_REPORT_TIMER, "Alert report timer"),
    (ANTI_WIPE_SERVICE, "Anti-wipe monitor service"),
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


@dataclass(frozen=True)
class UnitStateInfo:
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str
    detail: Optional[str] = None
    properties: Dict[str, str] = field(default_factory=dict)

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

DEPENDENCY_KIND_TIMER = "timer"
DEPENDENCY_KIND_SERVICE = "service"


class UnitDependency(NamedTuple):
    unit: str
    description: str
    kind: str = DEPENDENCY_KIND_TIMER


CONFIG_FEATURE_DEPENDENCIES = {
    "NN_IDS_SANITIZE": (
        "Packet sanitization",
        (
            UnitDependency("nn_ids_sanitize.timer", "Dataset sanitization timer"),
            UnitDependency(
                "nn_ids_sanitize.service",
                "Dataset sanitization service",
                DEPENDENCY_KIND_SERVICE,
            ),
        ),
    ),
    "NN_IDS_AUTOBLOCK": (
        "Automatic IP blocking",
        (
            UnitDependency("nn_ids_autoblock.timer", "Automatic blocking timer"),
            UnitDependency(
                "nn_ids_autoblock.service",
                "Automatic blocking service",
                DEPENDENCY_KIND_SERVICE,
            ),
        ),
    ),
    "NN_IDS_THREAT_FEED": (
        "Threat feed updates",
        (
            UnitDependency(
                "threat_feed_blocklist.timer", "Threat feed update timer"
            ),
            UnitDependency(
                "threat_feed_blocklist.service",
                "Threat feed update service",
                DEPENDENCY_KIND_SERVICE,
            ),
        ),
    ),
    "NN_IDS_NOTIFY": (
        "Notification delivery",
        (
            UnitDependency("nn_ids_report.timer", "Notification report timer"),
            UnitDependency(
                "nn_ids_report.service",
                "Notification report service",
                DEPENDENCY_KIND_SERVICE,
            ),
        ),
    ),
}


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


def _read_tail_lines(path: Path, *, max_bytes: int = 16384) -> Tuple[List[str], Optional[str]]:
    """Return trailing lines from ``path`` or an error message."""

    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            offset = max(size - max_bytes, 0)
            handle.seek(offset)
            data = handle.read().decode("utf-8", errors="replace")
    except OSError as exc:
        return [], f"unable to read {path}: {exc}"

    lines = data.splitlines()
    if offset > 0 and lines:
        lines = lines[1:]
    return lines, None


def _parse_iso_timestamp(value: str) -> Optional[datetime]:
    cleaned = (value or "").strip()
    if not cleaned:
        return None
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def _format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{size} B"


def _format_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _parse_snapshot_timestamp(name: str) -> Optional[datetime]:
    try:
        parsed = datetime.strptime(name, SNAPSHOT_TIMESTAMP_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _audit_snapshot_path(label: str, path: Path) -> Tuple[List[str], bool]:
    lines: List[str] = []
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        lines.append(f"⚠ {label}: missing ({path}).")
        return lines, False
    except OSError as exc:
        lines.append(f"⚠ {label}: unable to stat {path}: {exc}.")
        return lines, False

    mode = stat_result.st_mode
    owner_text = _describe_owner(stat_result.st_uid, stat_result.st_gid)
    mode_text = _format_mode(mode)
    permissions = stat.S_IMODE(mode)
    healthy = True

    if stat.S_ISLNK(mode):
        lines.append(f"⚠ {label}: is a symbolic link ({path}); store snapshots in a regular directory.")
        healthy = False
    if permissions & stat.S_IWOTH:
        lines.append(f"⚠ {label}: world-writable (mode {mode_text}); restrict permissions.")
        healthy = False
    if permissions & stat.S_IWGRP:
        lines.append(f"⚠ {label}: group-writable (mode {mode_text}); tighten permissions.")
        healthy = False

    allowed_uids = {0, os.getuid()}
    if stat_result.st_uid not in allowed_uids:
        lines.append(f"⚠ {label}: owned by {owner_text}; expected root or the current operator.")
        healthy = False

    if healthy:
        lines.append(f"{label}: secure ({owner_text} {mode_text}).")

    return lines, healthy


def _read_snapshot_hash_file(hash_path: Path) -> Tuple[Optional[str], Optional[str]]:
    try:
        text = hash_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return None, f"unable to read {hash_path}: {exc}"

    token = text.split()[0] if text else ""
    if len(token) != 64:
        descriptor = token or "(empty)"
        return None, f"hash {descriptor} invalid; expected 64 hex characters"

    try:
        int(token, 16)
    except ValueError:
        return None, f"hash {token} contains non-hex characters"

    return token.lower(), None


def _inspect_snapshot_dataset_archive(
    snapshot_name: str, archive_path: Path
) -> Tuple[List[str], bool]:
    lines: List[str] = []

    try:
        with tarfile.open(archive_path, "r:gz") as handle:
            try:
                members = handle.getmembers()
            except tarfile.TarError as exc:
                lines.append(
                    f"⚠ {snapshot_name}: unable to enumerate {archive_path}: {exc}."
                )
                return lines, False
    except (tarfile.TarError, OSError) as exc:
        lines.append(
            f"⚠ {snapshot_name}: dataset archive {archive_path} unreadable ({exc})."
        )
        return lines, False

    if not members:
        lines.append(
            f"⚠ {snapshot_name}: dataset archive {archive_path} empty; confirm snapshot job captured data."
        )
        return lines, False

    healthy = True
    top_level: Set[str] = set()
    file_count = 0

    for member in members:
        name = member.name
        normalized = Path(name)

        if normalized.is_absolute() or any(part in {"..", ""} for part in normalized.parts):
            lines.append(
                f"⚠ {snapshot_name}: dataset archive entry {name!r} is unsafe; recreate snapshot."
            )
            healthy = False

        if member.issym() or member.islnk():
            lines.append(
                f"⚠ {snapshot_name}: dataset archive embeds link {name!r}; remove symlinks from dataset."
            )
            healthy = False

        if member.ischr() or member.isblk() or member.isfifo():
            lines.append(
                f"⚠ {snapshot_name}: dataset archive contains special file {name!r}; prune dataset contents."
            )
            healthy = False

        if member.isfile():
            file_count += 1

        parts = normalized.parts
        if parts:
            top_level.add(parts[0])

    if top_level != {SNAPSHOT_DATASET_TOP_LEVEL}:
        lines.append(
            f"⚠ {snapshot_name}: dataset archive top-level entries {sorted(top_level)}; expected only '{SNAPSHOT_DATASET_TOP_LEVEL}'."
        )
        healthy = False

    if file_count == 0:
        lines.append(
            f"⚠ {snapshot_name}: dataset archive contains no regular files; verify capture succeeded."
        )
        healthy = False
    else:
        lines.append(
            f"{snapshot_name}: dataset archive contains {file_count} files under {SNAPSHOT_DATASET_TOP_LEVEL}."
        )

    return lines, healthy


def _describe_snapshot_artifact(
    snapshot_dir: Path, artifact: str, hash_name: str, label: str
) -> Tuple[List[str], bool]:
    lines: List[str] = []
    snapshot_name = snapshot_dir.name
    artifact_path = snapshot_dir / artifact
    hash_path = snapshot_dir / hash_name

    if not artifact_path.exists():
        lines.append(
            f"⚠ {snapshot_name}: missing {label.lower()} ({artifact_path})."
        )
        return lines, False
    if not artifact_path.is_file():
        lines.append(
            f"⚠ {snapshot_name}: {artifact_path} is not a regular file; rerun snapshot."
        )
        return lines, False

    security_lines, security_ok = _audit_snapshot_path(
        f"{snapshot_name} {label}", artifact_path
    )
    lines.extend(security_lines)

    if not hash_path.exists():
        lines.append(
            f"⚠ {snapshot_name}: missing {label.lower()} hash file ({hash_path})."
        )
        return lines, False
    if not hash_path.is_file():
        lines.append(
            f"⚠ {snapshot_name}: hash file {hash_path} is not a regular file; rerun snapshot."
        )
        return lines, False

    hash_security, hash_ok = _audit_snapshot_path(
        f"{snapshot_name} {label} hash", hash_path
    )
    lines.extend(hash_security)

    digest, error = _read_snapshot_hash_file(hash_path)
    if error:
        lines.append(f"⚠ {snapshot_name}: {label.lower()} {error}.")
        return lines, False

    computed = _compute_file_sha256(artifact_path)
    if computed is None:
        lines.append(
            f"⚠ {snapshot_name}: unable to compute hash for {artifact_path}."
        )
        return lines, False

    if computed.lower() != digest:
        lines.append(
            f"⚠ {snapshot_name}: {label.lower()} digest mismatch ({computed.lower()} != {digest})."
        )
        return lines, False

    try:
        size = artifact_path.stat().st_size
    except OSError as exc:
        lines.append(
            f"⚠ {snapshot_name}: unable to stat {artifact_path}: {exc}."
        )
        return lines, False

    if size <= 0:
        lines.append(
            f"⚠ {snapshot_name}: {label.lower()} file empty; verify snapshot job."
        )
        return lines, False

    size_text = _format_bytes(size)
    lines.append(
        f"{snapshot_name}: {label} verified ({size_text}, sha256 {digest})."
    )

    dataset_lines: List[str] = []
    dataset_ok = True
    if artifact == SNAPSHOT_DATASET_ARCHIVE:
        dataset_lines, dataset_ok = _inspect_snapshot_dataset_archive(
            snapshot_name, artifact_path
        )
        lines.extend(dataset_lines)

    return lines, security_ok and hash_ok and dataset_ok


def _summarize_snapshot_directory(snapshot_dir: Path) -> Tuple[List[str], bool]:
    lines: List[str] = []
    healthy = True

    for artifact, hash_name, label in SNAPSHOT_ARTIFACTS:
        artifact_lines, artifact_ok = _describe_snapshot_artifact(
            snapshot_dir, artifact, hash_name, label
        )
        lines.extend(artifact_lines)
        healthy = healthy and artifact_ok

    try:
        entries = list(snapshot_dir.iterdir())
    except OSError as exc:
        lines.append(
            f"⚠ {snapshot_dir.name}: unable to enumerate contents ({exc})."
        )
        return lines, False

    expected = {name for name, _, _ in SNAPSHOT_ARTIFACTS} | {
        hash_name for _, hash_name, _ in SNAPSHOT_ARTIFACTS
    }
    for entry in entries:
        if entry.name in expected:
            continue
        lines.append(
            f"⚠ {snapshot_dir.name}: unexpected entry {entry.name}; prune stray files."
        )
        healthy = False

    return lines, healthy


def analyze_snapshot_integrity() -> List[str]:
    lines: List[str] = []
    root, candidates = resolve_snapshot_root()
    candidate_text = ", ".join(str(path) for path in candidates)

    if root is None:
        return [
            f"⚠ Snapshot root not found; expected under {candidate_text}."
        ]

    security_lines, _ = _audit_snapshot_path("Snapshot root", root)
    lines.extend(security_lines)

    try:
        entries = list(root.iterdir())
    except OSError as exc:
        lines.append(f"⚠ Unable to enumerate snapshot root {root}: {exc}.")
        return lines

    snapshots: List[Tuple[datetime, Path]] = []
    for entry in entries:
        if entry.is_dir():
            timestamp = _parse_snapshot_timestamp(entry.name)
            if timestamp is None:
                lines.append(
                    f"⚠ Unexpected directory {entry.name} in snapshot root; use YYYYMMDDHHMMSS naming."
                )
                continue
            snapshots.append((timestamp, entry))
        else:
            lines.append(
                f"⚠ Unexpected file {entry.name} in snapshot root; keep only timestamped directories."
            )

    if not snapshots:
        lines.append(
            f"⚠ No snapshots present under {root}; run nn_ids_snapshot.py or enable nn_ids_snapshot.timer."
        )
        return lines

    snapshots.sort(key=lambda item: item[0])
    now = datetime.now(timezone.utc)
    latest_timestamp, latest_path = snapshots[-1]

    if latest_timestamp > now + SNAPSHOT_CLOCK_SKEW:
        skew = latest_timestamp - now
        lines.append(
            f"⚠ Latest snapshot {latest_path.name} timestamp {latest_timestamp.isoformat()} is {_format_duration(skew)} ahead of system clock."
        )

    age = now - latest_timestamp
    age_text = _format_duration(age)
    if age > SNAPSHOT_STALE_THRESHOLD:
        lines.append(
            f"⚠ Latest snapshot {latest_path.name} captured {age_text} ago; snapshots are stale."
        )
    else:
        lines.append(
            f"Latest snapshot {latest_path.name} captured {age_text} ago."
        )

    if len(snapshots) < 2:
        lines.append(
            "⚠ Only one snapshot available; schedule recurring captures for redundancy."
        )

    if len(snapshots) > SNAPSHOT_VALIDATION_LIMIT:
        lines.append(
            f"Validating latest {SNAPSHOT_VALIDATION_LIMIT} snapshots out of {len(snapshots)} discovered."
        )

    for timestamp, path in snapshots[-SNAPSHOT_VALIDATION_LIMIT:]:
        if timestamp > now + SNAPSHOT_CLOCK_SKEW and path != latest_path:
            skew = timestamp - now
            lines.append(
                f"⚠ Snapshot {path.name} timestamp {timestamp.isoformat()} is {_format_duration(skew)} ahead of system clock."
            )
        directory_lines, _ = _audit_snapshot_path(f"Snapshot {path.name}", path)
        lines.extend(directory_lines)
        artifact_lines, _ = _summarize_snapshot_directory(path)
        lines.extend(artifact_lines)

    return lines


def resolve_snapshot_root() -> Tuple[Optional[Path], Sequence[Path]]:
    for candidate in SNAPSHOT_CANDIDATES:
        if candidate.exists():
            return candidate, SNAPSHOT_CANDIDATES
    return None, SNAPSHOT_CANDIDATES


def _extract_logrotate_patterns(line: str) -> List[str]:
    patterns: List[str] = []
    for token in line.split():
        cleaned = token.strip().strip('"')
        if not cleaned or cleaned == "{":
            continue
        if cleaned.startswith("/"):
            patterns.append(cleaned)
    return patterns


def _parse_logrotate_blocks(text: str) -> List[Tuple[str, List[str]]]:
    blocks: List[Tuple[str, List[str]]] = []
    current_patterns: List[str] = []
    block_lines: List[str] = []
    in_block = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not in_block:
            if stripped.endswith("{") and stripped.startswith("/"):
                current_patterns = _extract_logrotate_patterns(stripped[:-1])
                block_lines = []
                in_block = True
                continue
            if stripped.startswith("/"):
                current_patterns = _extract_logrotate_patterns(stripped)
                continue
            if stripped == "{" and current_patterns:
                block_lines = []
                in_block = True
                continue
        else:
            if stripped == "}":
                for pattern in current_patterns:
                    cleaned = pattern.strip()
                    if cleaned:
                        blocks.append((cleaned, list(block_lines)))
                current_patterns = []
                block_lines = []
                in_block = False
                continue
            block_lines.append(stripped)

    return blocks


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _detect_logrotate_state_path(text: str) -> Optional[Path]:
    brace_depth = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if brace_depth == 0 and stripped.lower().startswith("state"):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                candidate = _strip_quotes(parts[1].split("#", 1)[0].strip())
                if candidate:
                    return Path(candidate)

        brace_depth += stripped.count("{")
        brace_depth -= stripped.count("}")
        if brace_depth < 0:
            brace_depth = 0

    return None


def _logrotate_state_candidates(config_text: Optional[str]) -> List[Path]:
    candidates: List[Path] = []
    if config_text:
        directive = _detect_logrotate_state_path(config_text)
        if directive and directive not in candidates:
            candidates.append(directive)
    for path in LOGROTATE_STATE_CANDIDATES:
        if path not in candidates:
            candidates.append(path)
    return candidates


def _parse_logrotate_state(text: str) -> Tuple[Dict[str, datetime], List[str]]:
    entries: Dict[str, datetime] = {}
    warnings: List[str] = []
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("logrotate state --") or stripped.startswith("#"):
            continue

        if not stripped.startswith('"'):
            warnings.append(
                f"⚠ State line {lineno} unrecognized: {stripped}"
            )
            continue

        try:
            _, remainder = stripped.split('"', 1)
            path_token, rest = remainder.split('"', 1)
        except ValueError:
            warnings.append(
                f"⚠ State line {lineno} malformed: {stripped}"
            )
            continue

        timestamp_text = rest.strip()
        if not timestamp_text:
            warnings.append(
                f"⚠ State entry for {path_token} missing timestamp"
            )
            continue

        parsed_time: Optional[datetime] = None
        for fmt in LOGROTATE_STATE_TIME_FORMATS:
            try:
                parsed_time = datetime.strptime(timestamp_text, fmt)
            except ValueError:
                continue
            else:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
                break

        if parsed_time is None:
            try:
                epoch = int(timestamp_text)
            except ValueError:
                warnings.append(
                    f"⚠ State entry for {path_token} has unknown timestamp {timestamp_text}"
                )
                continue
            parsed_time = datetime.fromtimestamp(epoch, timezone.utc)

        entries[path_token] = parsed_time

    return entries, warnings


def _parse_systemd_timestamp(value: str) -> Optional[datetime]:
    cleaned = (value or "").strip()
    if not cleaned or cleaned.lower() == "n/a":
        return None
    if cleaned.isdigit():
        try:
            micros = int(cleaned)
        except ValueError:
            pass
        else:
            if micros <= 0:
                return None
            return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)

    for fmt in SYSTEMD_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed

    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def _run_timedatectl(args: Sequence[str]) -> Tuple[Optional[str], Optional[str]]:
    if not TIMEDATECTL_PATH:
        return None, "timedatectl unavailable"
    command = [TIMEDATECTL_PATH, *args]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return None, f"Unable to execute {' '.join(command)}: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if not detail:
            detail = f"exit code {result.returncode}"
        return None, detail
    return result.stdout or "", None


def _parse_key_value_output(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _timedatectl_show() -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    output, error = _run_timedatectl(["show"])
    if output is None:
        return None, error
    return _parse_key_value_output(output), None


def _timedatectl_show_timesync() -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    output, error = _run_timedatectl(["show-timesync"])
    if output is None:
        return None, error
    return _parse_key_value_output(output), None


def _chronyc_tracking(log_errors: bool) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    if not CHRONYC_PATH:
        return None, "chronyc unavailable"
    command = [CHRONYC_PATH, "tracking"]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return None, f"Unable to execute {' '.join(command)}: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if not detail:
            detail = f"exit code {result.returncode}"
        if log_errors:
            return None, detail
        return None, None
    data: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data, None


def _parse_bool_text(value: str) -> Optional[bool]:
    cleaned = (value or "").strip().lower()
    if cleaned in {"yes", "y", "true", "1", "on"}:
        return True
    if cleaned in {"no", "n", "false", "0", "off"}:
        return False
    return None


def _parse_microseconds_delta(value: str) -> Optional[timedelta]:
    text = (value or "").strip()
    if not text:
        return None
    try:
        micros = int(text)
    except ValueError:
        return None
    return timedelta(microseconds=micros)


def _parse_first_float(value: str) -> Optional[float]:
    text = (value or "").strip()
    if not text:
        return None
    token = text.split()[0]
    try:
        return float(token)
    except ValueError:
        return None


def _describe_logrotate_timer_schedule(properties: Dict[str, str]) -> List[str]:
    lines: List[str] = []
    now = datetime.now(timezone.utc)

    schedule_raw = (
        properties.get("OnCalendar")
        or properties.get("TimersCalendar")
        or ""
    )
    schedule_clean = " ".join(schedule_raw.split())
    if schedule_clean and schedule_clean.lower() != "n/a":
        lines.append(f"Schedule: {schedule_clean}.")
    else:
        lines.append("⚠ logrotate.timer OnCalendar schedule unavailable; inspect the unit file.")

    last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
    if last_trigger is None:
        lines.append("⚠ logrotate.timer has not triggered yet; run systemctl start logrotate.timer.")
    else:
        skew = last_trigger - now
        if skew > LOGROTATE_STATE_CLOCK_SKEW:
            lines.append(
                f"⚠ logrotate.timer last trigger {last_trigger.isoformat()} is {_format_duration(skew)} ahead of the system clock."
            )
        age = now - last_trigger
        if age >= timedelta(0):
            lines.append(f"Last triggered {_format_duration(age)} ago.")
            if age > LOGROTATE_ROTATION_STALE + LOGROTATE_TIMER_GRACE:
                lines.append(
                    f"⚠ logrotate.timer last trigger {_format_duration(age)} ago exceeds daily cadence; investigate the schedule."
                )
        else:
            lines.append(
                f"⚠ logrotate.timer last trigger scheduled in {_format_duration(-age)}; verify system time alignment."
            )

    next_trigger = _parse_systemd_timestamp(
        properties.get("NextElapseUSecRealtime", "")
    )
    if next_trigger is None:
        lines.append("⚠ logrotate.timer next run unknown; verify OnCalendar configuration.")
    else:
        delta = next_trigger - now
        if delta < -LOGROTATE_STATE_CLOCK_SKEW:
            lines.append(
                f"⚠ logrotate.timer next run overdue by {_format_duration(-delta)}; reload or restart the timer."
            )
        else:
            lines.append(f"Next run in {_format_duration(delta)}.")
            if delta > LOGROTATE_TIMER_MAX_INTERVAL:
                lines.append(
                    f"⚠ logrotate.timer next run in {_format_duration(delta)} exceeds daily cadence; adjust the schedule."
                )

    return lines


def _enumerate_insecure_log_ancestors(log_path: Path) -> Tuple[List[str], Optional[str]]:
    issues: List[str] = []

    for ancestor in log_path.parents:
        if ancestor == log_path.parent:
            continue
        if ancestor == Path(ancestor.anchor):
            break
        try:
            stat_result = ancestor.lstat()
        except OSError as exc:
            return [], f"unable to stat ancestor {ancestor}: {exc}"

        mode = stat_result.st_mode
        try:
            owner = pwd.getpwuid(stat_result.st_uid).pw_name
        except KeyError:
            owner = str(stat_result.st_uid)
        try:
            group = grp.getgrgid(stat_result.st_gid).gr_name
        except KeyError:
            group = str(stat_result.st_gid)

        if stat.S_ISLNK(mode):
            issues.append(f"ancestor {ancestor} is a symlink")
            continue

        permissions = stat.S_IMODE(mode)
        if permissions & stat.S_IWOTH:
            issues.append(f"ancestor {ancestor} world-writable")
        if permissions & stat.S_IWGRP and group not in SECURE_LOG_GROUPS:
            issues.append(
                f"ancestor {ancestor} group-writable (group {group})"
            )
        if owner != "root":
            issues.append(f"ancestor {ancestor} owner {owner}")

    return issues, None


def _analyze_logrotate_olddir(
    log_path: Path, directive: str
) -> Tuple[List[str], Optional[str]]:
    """Validate an olddir directive and summarize its security posture."""

    raw = directive.split("#", 1)[0].strip()
    tokens = raw.split()
    if len(tokens) < 2:
        return (["olddir directive incomplete"], None)

    candidate_token = _strip_quotes(tokens[1])
    if not candidate_token:
        return (["olddir directive missing directory"], None)

    olddir_path = Path(candidate_token)
    if not olddir_path.is_absolute():
        return ([f"olddir {olddir_path} not absolute"], None)

    try:
        stat_result = olddir_path.lstat()
    except FileNotFoundError:
        return ([f"olddir {olddir_path} missing"], None)
    except OSError as exc:
        return ([f"olddir {olddir_path} unreadable ({exc})"], None)

    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        return ([f"olddir {olddir_path} is a symlink"], None)
    if not stat.S_ISDIR(mode):
        return ([f"olddir {olddir_path} not a directory"], None)

    try:
        log_parent_stat = log_path.parent.lstat()
    except OSError as exc:
        return (
            [
                f"olddir {olddir_path} unable to stat log directory {log_path.parent} ({exc})"
            ],
            None,
        )

    issues: List[str] = []
    if stat_result.st_dev != log_parent_stat.st_dev:
        issues.append(
            f"olddir {olddir_path} on different filesystem from {log_path.parent}"
        )
    permissions = stat.S_IMODE(mode)
    try:
        owner = pwd.getpwuid(stat_result.st_uid).pw_name
    except KeyError:
        owner = str(stat_result.st_uid)
    try:
        group = grp.getgrgid(stat_result.st_gid).gr_name
    except KeyError:
        group = str(stat_result.st_gid)

    if permissions & stat.S_IWOTH:
        issues.append("olddir world-writable")
    if permissions & (stat.S_IROTH | stat.S_IXOTH):
        issues.append("olddir world-accessible")
    if permissions & stat.S_IWGRP and group not in SECURE_LOG_GROUPS:
        issues.append(f"olddir group-writable (group {group})")
    if owner != "root":
        issues.append(f"olddir owner {owner}")
    if group not in SECURE_LOG_GROUPS:
        issues.append(f"olddir group {group}")

    ancestor_issues, ancestor_error = _enumerate_insecure_log_ancestors(
        olddir_path / log_path.name
    )
    if ancestor_error:
        return ([f"olddir {olddir_path} ancestor audit failed ({ancestor_error})"], None)
    if ancestor_issues:
        issues.extend(ancestor_issues)

    if issues:
        return ([f"olddir {olddir_path} {'; '.join(issues)}"], None)

    owner_text = _describe_owner(stat_result.st_uid, stat_result.st_gid)
    return (
        [],
        f"olddir {olddir_path} ({owner_text} {_format_mode(mode)})",
    )


def _audit_logrotate_state_metadata(
    state_path: Path,
) -> Tuple[List[str], Optional[str]]:
    """Return metadata issues and a secure summary for the logrotate state file."""

    try:
        stat_result = state_path.lstat()
    except FileNotFoundError:
        return ([f"Logrotate state file missing ({state_path})"], None)
    except OSError as exc:
        return ([f"Unable to stat logrotate state file {state_path}: {exc}"], None)

    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        return ([f"Logrotate state file {state_path} is a symbolic link"], None)
    if not stat.S_ISREG(mode):
        return ([f"Logrotate state file {state_path} is not a regular file"], None)

    permissions = stat.S_IMODE(mode)
    try:
        owner = pwd.getpwuid(stat_result.st_uid).pw_name
    except KeyError:
        owner = str(stat_result.st_uid)
    try:
        group = grp.getgrgid(stat_result.st_gid).gr_name
    except KeyError:
        group = str(stat_result.st_gid)

    issues: List[str] = []
    if permissions & stat.S_IWOTH:
        issues.append("world-writable")
    if permissions & (stat.S_IROTH | stat.S_IXOTH):
        issues.append("world-accessible")
    if permissions & stat.S_IWGRP and group not in SECURE_LOG_GROUPS:
        issues.append(f"group-writable (group {group})")
    if owner != "root":
        issues.append(f"owner {owner}")
    if group not in SECURE_LOG_GROUPS:
        issues.append(f"group {group}")

    parent = state_path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        return ([f"Unable to stat logrotate state directory {parent}: {exc}"], None)

    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    try:
        parent_owner = pwd.getpwuid(parent_stat.st_uid).pw_name
    except KeyError:
        parent_owner = str(parent_stat.st_uid)
    try:
        parent_group = grp.getgrgid(parent_stat.st_gid).gr_name
    except KeyError:
        parent_group = str(parent_stat.st_gid)

    if stat.S_ISLNK(parent_stat.st_mode):
        issues.append(f"parent {parent} is a symbolic link")
    if parent_mode & stat.S_IWOTH:
        issues.append(f"parent {parent} world-writable")
    if parent_mode & stat.S_IWGRP and parent_group not in SECURE_LOG_GROUPS:
        issues.append(
            f"parent {parent} group-writable (group {parent_group})"
        )
    if parent_owner != "root":
        issues.append(f"parent {parent} owner {parent_owner}")

    ancestor_issues, ancestor_error = _enumerate_insecure_log_ancestors(state_path)
    if ancestor_error:
        return ([ancestor_error], None)
    if ancestor_issues:
        issues.extend(ancestor_issues)

    if issues:
        joined = "; ".join(issues)
        return (
            [
                f"Logrotate state file {state_path} insecure ({joined}); harden permissions to protect rotation metadata"
            ],
            None,
        )

    owner_text = _describe_owner(stat_result.st_uid, stat_result.st_gid)
    return (
        [],
        f"Logrotate state file {state_path} secure ({owner_text} {_format_mode(mode)})",
    )


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


def resolve_threat_feed_endpoints(
    config: Dict[str, str]
) -> Tuple[List[str], List[str]]:
    """Return configured threat feed endpoints and associated warnings."""

    raw_value = config.get(THREAT_FEED_ENDPOINT_KEY, "")
    endpoints: List[str] = []
    notes: List[str] = []

    if raw_value:
        for entry in raw_value.split(","):
            candidate = entry.strip()
            if not candidate:
                continue
            parsed = urlsplit(candidate)
            if not parsed.scheme or not parsed.netloc:
                notes.append(
                    f"Threat feed endpoint {candidate!r} missing scheme or host; ignoring entry."
                )
                continue
            endpoints.append(candidate)

    if not endpoints:
        if raw_value:
            notes.append(
                "Threat feed endpoint list resolved to zero valid entries; using built-in defaults."
            )
        else:
            notes.append(
                f"Threat feed endpoints defaulting to built-in feeds; set {THREAT_FEED_ENDPOINT_KEY} to customize."
            )
        endpoints = list(THREAT_FEED_DEFAULT_ENDPOINTS)

    unique: List[str] = []
    seen: Set[str] = set()
    for endpoint in endpoints:
        if endpoint in seen:
            continue
        unique.append(endpoint)
        seen.add(endpoint)

    return unique, notes


def _perform_threat_feed_probe(url: str) -> Tuple[bool, str]:
    try:
        request = Request(url, method="HEAD")  # type: ignore[call-arg]
    except TypeError:
        request = Request(url)
        request.get_method = lambda: "HEAD"  # type: ignore[attr-defined]

    request.add_header("User-Agent", THREAT_FEED_USER_AGENT)

    try:
        with urlopen(request, timeout=THREAT_FEED_PROBE_TIMEOUT) as response:
            status = getattr(response, "status", None) or response.getcode()
            return True, f"HTTP {status}"
    except HTTPError as exc:
        if exc.code == 405:
            return _perform_threat_feed_probe_get(url)
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)
    except Exception as exc:
        return False, str(exc)


def _perform_threat_feed_probe_get(url: str) -> Tuple[bool, str]:
    request = Request(url)
    request.add_header("User-Agent", THREAT_FEED_USER_AGENT)
    request.add_header("Range", "bytes=0-0")

    try:
        with urlopen(request, timeout=THREAT_FEED_PROBE_TIMEOUT) as response:
            status = getattr(response, "status", None) or response.getcode()
            try:
                response.read(1)
            except Exception:
                pass
            return True, f"HTTP {status}"
    except HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)
    except Exception as exc:
        return False, str(exc)


def probe_threat_feed_endpoint(url: str) -> Tuple[bool, str]:
    """Probe an endpoint with caching to avoid repeated network calls."""

    now = datetime.now(timezone.utc)
    cached = _THREAT_FEED_PROBE_CACHE.get(url)
    if cached:
        timestamp, success, detail = cached
        if now - timestamp <= THREAT_FEED_PROBE_TTL:
            return success, detail

    success, detail = _perform_threat_feed_probe(url)
    _THREAT_FEED_PROBE_CACHE[url] = (now, success, detail)
    return success, detail


def detect_config() -> Tuple[Optional[Path], Dict[str, str]]:
    path, data, _, _ = detect_config_with_diagnostics()
    return path, data


def resolve_config_path() -> Path:
    path, _ = detect_config()
    if path:
        return path
    return CONFIG_CANDIDATES[-1]


def resolve_logrotate_path() -> Optional[Path]:
    for candidate in LOGROTATE_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def resolve_logrotate_state_path(config_text: Optional[str] = None) -> Tuple[Optional[Path], List[Path]]:
    candidates = _logrotate_state_candidates(config_text)
    for candidate in candidates:
        if candidate.exists():
            return candidate, candidates
    return None, candidates


def resolve_ssh_access_file(
    primary: Path, fallbacks: Sequence[Path]
) -> Tuple[Optional[Path], List[str]]:
    """Return an SSH access-control path and associated advisory messages."""

    notes: List[str] = []

    if primary.exists():
        if not primary.is_file():
            notes.append(f"{primary} is not a regular file.")
            return None, notes
        return primary, notes

    for candidate in fallbacks:
        if not candidate.exists():
            continue
        if not candidate.is_file():
            notes.append(f"{candidate} is not a regular file.")
            return None, notes
        notes.append(
            f"Currently using {candidate}; relocate it to {primary} so automation and hygiene checks align."
        )
        return candidate, notes

    notes.append(f"Missing {primary}.")
    return None, notes


def parse_ssh_access_entries(
    path: Path,
) -> Tuple[List[ipaddress._BaseNetwork], List[str], List[str], List[str]]:
    """Parse SSH access control entries and return metadata lists."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], [f"Unable to read {path}: {exc}"], [], []

    networks: List[ipaddress._BaseNetwork] = []
    invalid: List[str] = []
    duplicates: List[str] = []
    ipv6_entries: List[str] = []
    seen: Dict[str, int] = {}

    for index, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(('#', ';')):
            continue

        candidate = stripped.split('#', 1)[0]
        candidate = candidate.split(';', 1)[0].strip()
        if not candidate:
            continue

        token = candidate.split()[0]
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            invalid.append(f"line {index}: {token}")
            continue

        normalized = str(network)
        if normalized in seen:
            duplicates.append(f"{normalized} (lines {seen[normalized]} & {index})")
            continue

        seen[normalized] = index
        networks.append(network)
        if network.version != 4:
            ipv6_entries.append(f"line {index}: {token}")

    return networks, invalid, duplicates, ipv6_entries


def _query_iptables_lines(args: Sequence[str]) -> Tuple[Optional[List[str]], Optional[str]]:
    """Return iptables output lines for ``args`` or an error description."""

    if IPTABLES_PATH is None:
        return None, "iptables binary not found"

    command = [IPTABLES_PATH, *args]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return None, str(exc)

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if not message:
            message = f"exit code {result.returncode}"
        return None, message

    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return lines, None


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


def _query_unit_state(
    unit: str, extra_properties: Sequence[str] = ()
) -> Optional[UnitStateInfo]:
    if not shutil.which("systemctl"):
        return None
    base_properties = ["LoadState", "ActiveState", "SubState", "UnitFileState"]
    property_names = list(dict.fromkeys([*base_properties, *extra_properties]))
    cmd = ["systemctl", "show", unit, "--no-page"]
    cmd.extend(f"--property={prop}" for prop in property_names)
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return UnitStateInfo("error", "", "", "", str(exc))

    values: Dict[str, str] = {prop: "" for prop in property_names}
    for line in (result.stdout or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            values[key] = value.strip()

    load_state = values.get("LoadState", "") or ""
    detail = (result.stderr or "").strip() or None

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        lowered = message.lower()
        if not load_state:
            if "not-found" in lowered:
                load_state = "not-found"
            elif "masked" in lowered:
                load_state = "masked"
            elif message:
                load_state = "error"
                detail = message
            else:
                load_state = "error"
        elif load_state == "not-found" and message:
            detail = message
        elif message and detail is None:
            detail = message

    if not load_state:
        load_state = "loaded"

    return UnitStateInfo(
        load_state=load_state,
        active_state=values.get("ActiveState", "") or "",
        sub_state=values.get("SubState", "") or "",
        unit_file_state=values.get("UnitFileState", "") or "",
        detail=detail,
        properties={prop: values.get(prop, "") for prop in extra_properties},
    )


def _format_unit_status(info: Optional[UnitStateInfo]) -> str:
    if info is None:
        return "unknown"
    load_state = info.load_state.lower()
    if load_state and load_state not in {"loaded", ""}:
        if info.detail and load_state == "error":
            return f"error ({info.detail})"
        return load_state
    status = info.active_state or "inactive"
    sub_state = info.sub_state
    if status == "active" and sub_state and sub_state not in {"running", "dead"}:
        return f"{status} ({sub_state})"
    return status


def _status_from_systemctl(unit: str) -> str:
    info = _query_unit_state(unit)
    return _format_unit_status(info)


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
        info = _query_unit_state(unit)
        status = _format_unit_status(info)
        normalized = status.lower()
        load_state = info.load_state.lower() if info else "unknown"
        unit_file_state = info.unit_file_state.lower() if info else ""
        if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
            color = COLOR_ERROR
        elif normalized in {"active", "active (waiting)", "running"}:
            color = COLOR_SUCCESS
        elif normalized in {"failed", "inactive", "dead"}:
            color = COLOR_ERROR
        else:
            color = COLOR_WARN
        detail = status
        if load_state not in {"loaded", "", "unknown"}:
            detail = f"{detail} (load: {load_state})"
        elif unit_file_state == "masked":
            detail = f"{detail} (masked)"
        elif info and info.detail and load_state == "error":
            detail = f"{detail} ({info.detail})"
        lines.append((f"{label}: {detail}", color))
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


def analyze_cpu_capacity() -> List[str]:
    """Summarize CPU load averages against expected headroom."""

    try:
        contents = LOADAVG_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return [f"⚠ Unable to read {LOADAVG_PATH}: {exc}."]

    if not contents:
        return [f"⚠ {LOADAVG_PATH} empty; cannot evaluate CPU load."]

    parts = contents.split()
    if len(parts) < 4:
        return [f"⚠ Unexpected format for {LOADAVG_PATH}: {contents!r}."]

    issues: List[str] = []
    loads: List[float] = []
    for idx, token in enumerate(parts[:3], start=1):
        try:
            loads.append(float(token))
        except ValueError:
            issues.append(
                f"⚠ Unable to parse {idx}-minute load average '{token}' from {LOADAVG_PATH}."
            )

    running: Optional[int] = None
    total_tasks: Optional[int] = None
    queue_token = parts[3]
    if "/" in queue_token:
        run_text, total_text = queue_token.split("/", 1)
        try:
            running = int(run_text)
            total_tasks = int(total_text)
        except ValueError:
            issues.append(
                f"⚠ Unable to parse runnable task counts '{queue_token}' from {LOADAVG_PATH}."
            )
    else:
        issues.append(
            f"⚠ Unexpected runnable task field '{queue_token}' in {LOADAVG_PATH}; expected 'running/total'."
        )

    if issues:
        return issues

    cpu_count = os.cpu_count() or 1
    per_cpu_lines: List[str] = []
    for threshold, load in zip(CPU_LOAD_THRESHOLDS, loads):
        per_cpu = load / cpu_count
        per_cpu_text = _format_number(per_cpu)
        limit_text = _format_number(threshold.max_per_cpu)
        summary = (
            f"{threshold.label}: load {load:.2f} "
            f"({per_cpu_text} per CPU across {cpu_count} cores)."
        )
        if per_cpu > threshold.max_per_cpu:
            per_cpu_lines.append(
                f"⚠ {summary} Keep load below {limit_text} per CPU to preserve IDS responsiveness."
            )
        else:
            per_cpu_lines.append(f"{summary} Within limit {limit_text} per CPU.")

    queue_lines: List[str] = []
    if running is not None:
        queue_ratio = running / cpu_count
        queue_ratio_text = _format_number(queue_ratio)
        limit_text = _format_number(CPU_RUN_QUEUE_MAX_PER_CPU)
        summary = (
            f"Run queue: {running} runnable tasks for {cpu_count} CPUs "
            f"({queue_ratio_text} per CPU)."
        )
        if queue_ratio > CPU_RUN_QUEUE_MAX_PER_CPU:
            queue_lines.append(
                f"⚠ {summary} Reduce contention to stay below {limit_text} per CPU."
            )
        else:
            queue_lines.append(f"{summary} Below limit {limit_text} per CPU.")

    if total_tasks is not None and total_tasks <= 0:
        queue_lines.append(
            f"⚠ Total task count reported as {total_tasks} in {LOADAVG_PATH}; verify kernel scheduling data."
        )

    return per_cpu_lines + queue_lines or ["No CPU load data available."]


def analyze_time_synchronization() -> List[str]:
    """Summarize host clock synchronization health."""

    lines: List[str] = []
    issues = False
    now = datetime.now(timezone.utc)

    def note(message: str) -> None:
        lines.append(message)

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    services_checked = False
    service_found = False
    service_running = False

    if shutil.which("systemctl"):
        for unit, description in TIME_SYNC_SERVICES:
            info = _query_unit_state(unit)
            if info is None:
                continue
            services_checked = True
            load_state = (info.load_state or "").lower()
            if load_state == "not-found":
                continue
            service_found = True
            status_text = _format_unit_status(info)
            if load_state != "loaded":
                warn(
                    f"{description} ({unit}) load state {load_state or 'unknown'}; reinstall or repair the unit."
                )
                continue
            active_state = (info.active_state or "").lower()
            if active_state in {"active", "activating", "running"}:
                service_running = True
                note(f"{description} ({unit}) {status_text}.")
            else:
                warn(
                    f"{description} ({unit}) is {status_text}; start the service to maintain clock sync."
                )
    elif shutil.which("systemctl") is None:
        note("systemctl unavailable; skipping NTP service status checks.")

    if services_checked:
        if not service_found:
            warn(
                "No supported NTP service detected; install systemd-timesyncd, chronyd, or ntpd to manage clock sync."
            )
        elif not service_running:
            warn("Time synchronization unit detected but inactive; enable it to keep clocks aligned.")

    sources = 0

    show_data, show_error = _timedatectl_show()
    if show_data:
        sources += 1
        system_sync = show_data.get("SystemClockSynchronized")
        if system_sync is not None:
            sync_flag = _parse_bool_text(system_sync)
            if sync_flag is False:
                warn("timedatectl reports the system clock unsynchronized; verify NTP reachability.")
            elif sync_flag is True:
                note("System clock reported as synchronized by timedatectl.")
            else:
                warn(f"Unable to interpret SystemClockSynchronized={system_sync} from timedatectl.")
        else:
            warn("timedatectl show omitted SystemClockSynchronized; update systemd-timesyncd.")

        ntp_sync = show_data.get("NTPSynchronized") or show_data.get("NTP")
        if ntp_sync is not None:
            ntp_flag = _parse_bool_text(ntp_sync)
            if ntp_flag is False:
                warn("timedatectl reports NTP unsynchronized; check upstream peers and firewall rules.")
            elif ntp_flag is True:
                note("NTP synchronization active according to timedatectl.")
            else:
                warn(f"Unable to interpret NTPSynchronized value {ntp_sync}; upgrade systemd.")
    elif show_error:
        if show_error == "timedatectl unavailable":
            warn("timedatectl unavailable; install systemd-timesyncd for detailed clock status.")
        else:
            warn(f"timedatectl show failed: {show_error}.")

    timesync_data: Optional[Dict[str, str]] = None
    if show_data is not None or TIMEDATECTL_PATH:
        timesync_data, timesync_error = _timedatectl_show_timesync()
        if timesync_data:
            sources += 1
            server = timesync_data.get("ServerName") or timesync_data.get("SystemNTPServer")
            address = timesync_data.get("ServerAddress") or timesync_data.get("ServerAddress6")
            if server:
                if address:
                    note(f"Active NTP server {server} ({address}).")
                else:
                    note(f"Active NTP server {server}.")
            else:
                warn("timedatectl show-timesync reported no active NTP server; review configuration.")

            state = (timesync_data.get("NTPState") or "").lower()
            if state and state not in {"synchronized", "sync", "active"}:
                warn(f"timedatectl reports NTP state {state or 'unknown'}; investigate time sync health.")

            last_sync: Optional[datetime] = None
            for key in (
                "LastSyncUSec",
                "LastSyncTimestamp",
                "LastSyncTime",
                "LastSuccessfulSync",
            ):
                candidate = timesync_data.get(key)
                if candidate:
                    last_sync = _parse_systemd_timestamp(candidate)
                if last_sync is not None:
                    break

            if last_sync is not None:
                skew = last_sync - now
                if skew > TIME_SYNC_CLOCK_SKEW:
                    warn(
                        f"Last synchronization {last_sync.isoformat()} leads system time by"
                        f" {_format_duration(skew)}; verify host clocks."
                    )
                else:
                    age = now - last_sync
                    note(f"Last synchronization {_format_duration(age)} ago.")
                    if age > TIME_SYNC_STALE_THRESHOLD:
                        warn(
                            "Last synchronization older than"
                            f" {_format_duration(TIME_SYNC_STALE_THRESHOLD)}; check NTP reachability."
                        )
            else:
                warn("Unable to determine last synchronization time from timedatectl.")

            offset_raw = timesync_data.get("OffsetUSec")
            if offset_raw:
                offset_delta = _parse_microseconds_delta(offset_raw)
                if offset_delta is None:
                    warn(f"timedatectl reported non-numeric OffsetUSec={offset_raw}.")
                else:
                    offset_ms = abs(offset_delta.total_seconds()) * 1000
                    limit_ms = TIME_SYNC_OFFSET_THRESHOLD.total_seconds() * 1000
                    if offset_ms > limit_ms:
                        warn(
                            f"Clock offset {offset_ms:.1f} ms exceeds {limit_ms:.0f} ms tolerance; adjust NTP peers."
                        )
                    else:
                        note(f"Clock offset {offset_ms:.1f} ms within tolerance.")

            poll_raw = timesync_data.get("PollIntervalUSec")
            if poll_raw:
                poll_delta = _parse_microseconds_delta(poll_raw)
                if poll_delta is None:
                    warn(f"PollIntervalUSec not numeric ({poll_raw}); update systemd-timesyncd.")
                elif poll_delta > TIME_SYNC_UPDATE_MAX:
                    warn(
                        f"NTP poll interval {_format_duration(poll_delta)} exceeds"
                        f" {_format_duration(TIME_SYNC_UPDATE_MAX)}; tighten scheduling."
                    )
        elif timesync_error and timesync_error != "timedatectl unavailable":
            warn(f"timedatectl show-timesync failed: {timesync_error}.")

    chrony_required = show_data is None and (TIMEDATECTL_PATH is None)
    chrony_data, chrony_error = _chronyc_tracking(log_errors=chrony_required)
    if chrony_data:
        sources += 1
        ref = chrony_data.get("Reference ID") or chrony_data.get("ReferenceID")
        if ref:
            note(f"Chrony reference {ref}.")

        stratum_raw = chrony_data.get("Stratum")
        if stratum_raw:
            token = stratum_raw.split()[0]
            try:
                stratum = int(token)
            except ValueError:
                warn(f"Chrony stratum value unexpected: {stratum_raw}.")
            else:
                if stratum > TIME_SYNC_STRATUM_MAX:
                    warn(
                        f"Chrony stratum {stratum} exceeds maximum {TIME_SYNC_STRATUM_MAX}; choose closer peers."
                    )
                else:
                    note(f"Chrony stratum {stratum}.")

        ref_time_raw = chrony_data.get("Ref time (UTC)")
        if ref_time_raw:
            parsed_ref: Optional[datetime] = None
            for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
                try:
                    parsed_ref = datetime.strptime(ref_time_raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                break
            if parsed_ref is None:
                warn(f"Unable to parse chronyc reference time '{ref_time_raw}'.")
            else:
                skew = parsed_ref - now
                if skew > TIME_SYNC_CLOCK_SKEW:
                    warn(
                        f"Chrony reference time {parsed_ref.isoformat()} leads system clock by"
                        f" {_format_duration(skew)}; inspect clock discipline."
                    )
                else:
                    age = now - parsed_ref
                    note(f"Chrony reference updated {_format_duration(age)} ago.")
                    if age > TIME_SYNC_STALE_THRESHOLD:
                        warn(
                            "Chrony reference older than"
                            f" {_format_duration(TIME_SYNC_STALE_THRESHOLD)}; investigate peer reachability."
                        )

        for label in ("System time", "Last offset", "RMS offset"):
            raw_value = chrony_data.get(label)
            if not raw_value:
                continue
            seconds = _parse_first_float(raw_value)
            if seconds is None:
                warn(f"Unable to parse chronyc {label.lower()} '{raw_value}'.")
                continue
            if abs(seconds) > TIME_SYNC_OFFSET_THRESHOLD.total_seconds():
                warn(
                    f"Chrony {label.lower()} {seconds * 1000:.1f} ms exceeds"
                    f" {TIME_SYNC_OFFSET_THRESHOLD.total_seconds() * 1000:.0f} ms tolerance."
                )
            else:
                note(f"Chrony {label.lower()} {seconds * 1000:.1f} ms within tolerance.")

        update_raw = chrony_data.get("Update interval")
        if update_raw:
            seconds = _parse_first_float(update_raw)
            if seconds is None:
                warn(f"Unable to parse chronyc update interval '{update_raw}'.")
            else:
                delta = timedelta(seconds=seconds)
                if delta > TIME_SYNC_UPDATE_MAX:
                    warn(
                        f"Chrony update interval {_format_duration(delta)} exceeds"
                        f" {_format_duration(TIME_SYNC_UPDATE_MAX)}."
                    )

        leap_status = chrony_data.get("Leap status")
        if leap_status and leap_status.strip().lower() != "normal":
            warn(f"Chrony leap status {leap_status}; clock discipline degraded.")
    elif chrony_required and chrony_error:
        warn(f"chronyc tracking failed: {chrony_error}.")

    if sources == 0:
        warn("Unable to collect time synchronization telemetry; deploy timedatectl or chrony utilities.")

    if not issues:
        lines.append("Time synchronization healthy and current.")

    return lines


def analyze_memory_capacity() -> List[str]:
    """Report available system memory and swap headroom."""

    try:
        contents = MEMINFO_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"⚠ Unable to read {MEMINFO_PATH}: {exc}."]

    meminfo: Dict[str, int] = {}
    issues: List[str] = []

    for line in contents.splitlines():
        if ":" not in line:
            continue
        key, remainder = line.split(":", 1)
        value_text = remainder.strip()
        if not value_text:
            continue
        parts = value_text.split()
        raw_value = parts[0]
        try:
            value = int(raw_value)
        except ValueError:
            issues.append(
                f"⚠ Unable to parse {key.strip()} from {MEMINFO_PATH}; value was {raw_value}."
            )
            continue
        unit = parts[1].lower() if len(parts) > 1 else ""
        if unit == "kb":
            value *= 1024
        meminfo[key.strip()] = value

    lines: List[str] = issues.copy()

    for threshold in MEMORY_CAPACITY_THRESHOLDS:
        total = meminfo.get("MemTotal")
        if total is None or total <= 0:
            lines.append(
                f"⚠ {threshold.label}: MemTotal missing or invalid in {MEMINFO_PATH};"
                " cannot evaluate available memory."
            )
            continue

        available = meminfo.get("MemAvailable")
        if available is None:
            fallback = meminfo.get("MemFree")
            if fallback is None:
                lines.append(
                    f"⚠ {threshold.label}: MemAvailable missing and no MemFree fallback;"
                    " cannot estimate available memory."
                )
                continue
            lines.append(
                "⚠ MemAvailable missing in /proc/meminfo; using MemFree as a conservative"
                " fallback for memory reporting."
            )
            available = fallback

        free_ratio = available / total
        memory_summary = (
            f"{threshold.label}: {_format_bytes(available)} available"
            f" ({_format_percent(free_ratio)}) of {_format_bytes(total)} total."
        )
        min_available = _format_bytes(threshold.min_available_bytes)
        min_available_percent = _format_percent(threshold.min_available_percent)

        below_bytes = available < threshold.min_available_bytes
        below_percent = free_ratio < threshold.min_available_percent

        if below_bytes or below_percent:
            requirements: List[str] = []
            if below_bytes:
                requirements.append(min_available)
            if below_percent:
                requirements.append(min_available_percent)
            requirement_text = " and ".join(requirements)
            lines.append(
                f"⚠ {memory_summary} Maintain at least {requirement_text} free to avoid"
                " memory pressure affecting IDS services."
            )
        else:
            lines.append(
                f"{memory_summary} Above minimum thresholds"
                f" ({min_available} and {min_available_percent} free)."
            )

        swap_total = meminfo.get("SwapTotal")
        swap_free = meminfo.get("SwapFree")

        if swap_total is None or swap_free is None:
            lines.append(
                f"⚠ {threshold.label}: Swap metrics missing in {MEMINFO_PATH};"
                " cannot confirm swap availability."
            )
            continue

        if swap_total <= 0:
            lines.append(
                f"⚠ {threshold.label}: Swap disabled or zero-sized; configure swap to provide"
                " burst capacity for IDS processes."
            )
            continue

        swap_ratio = swap_free / swap_total
        swap_summary = (
            f"Swap: {_format_bytes(swap_free)} free"
            f" ({_format_percent(swap_ratio)}) of {_format_bytes(swap_total)} total."
        )
        min_swap = _format_bytes(threshold.min_swap_free_bytes)
        min_swap_percent = _format_percent(threshold.min_swap_percent)

        below_swap_bytes = swap_free < threshold.min_swap_free_bytes
        below_swap_percent = swap_ratio < threshold.min_swap_percent

        if below_swap_bytes or below_swap_percent:
            requirements: List[str] = []
            if below_swap_bytes:
                requirements.append(min_swap)
            if below_swap_percent:
                requirements.append(min_swap_percent)
            requirement_text = " and ".join(requirements)
            lines.append(
                f"⚠ {swap_summary} Maintain at least {requirement_text} swap free"
                " to absorb sudden memory spikes."
            )
        else:
            lines.append(
                f"{swap_summary} Above minimum thresholds"
                f" ({min_swap} and {min_swap_percent} free)."
            )

    if not lines:
        return ["No memory capacity targets evaluated."]
    return lines


def analyze_disk_capacity() -> List[str]:
    """Report free space for critical IDS volumes."""

    lines: List[str] = []

    for threshold in DISK_USAGE_THRESHOLDS:
        resolved: Optional[Path] = None
        for candidate in threshold.candidates:
            if candidate.exists():
                resolved = candidate
                break

        if resolved is None:
            locations = ", ".join(str(path) for path in threshold.candidates)
            lines.append(
                f"⚠ {threshold.label}: path not found; expected under {locations}."
            )
            continue

        try:
            usage = shutil.disk_usage(resolved)
        except OSError as exc:
            lines.append(
                f"⚠ {threshold.label}: unable to inspect {resolved}: {exc}."
            )
            continue

        total = usage.total
        free = usage.free
        if total <= 0:
            lines.append(
                f"⚠ {threshold.label}: reported size zero for {resolved}; verify filesystem."
            )
            continue

        free_ratio = free / total
        free_text = _format_bytes(free)
        total_text = _format_bytes(total)
        percent_text = _format_percent(free_ratio)
        min_bytes_text = _format_bytes(threshold.min_free_bytes)
        min_percent_text = _format_percent(threshold.min_free_percent)
        summary = (
            f"{threshold.label}: {free_text} free ({percent_text}) of {total_text} at {resolved}."
        )

        below_bytes = free < threshold.min_free_bytes
        below_percent = free_ratio < threshold.min_free_percent

        if below_bytes or below_percent:
            requirements: List[str] = []
            if below_bytes:
                requirements.append(min_bytes_text)
            if below_percent:
                requirements.append(min_percent_text)
            requirement_text = " and ".join(requirements)
            lines.append(
                f"⚠ {summary} Maintain at least {requirement_text} free to avoid service disruption."
            )
        else:
            lines.append(
                f"{summary} Above minimum thresholds ({min_bytes_text} and {min_percent_text} free)."
            )

    if not lines:
        return ["No disk capacity targets evaluated."]
    return lines


def analyze_inode_capacity() -> List[str]:
    """Report free inode availability for critical volumes."""

    lines: List[str] = []

    for threshold in INODE_USAGE_THRESHOLDS:
        resolved: Optional[Path] = None
        for candidate in threshold.candidates:
            if candidate.exists():
                resolved = candidate
                break

        if resolved is None:
            locations = ", ".join(str(path) for path in threshold.candidates)
            lines.append(
                f"⚠ {threshold.label}: path not found; expected under {locations}."
            )
            continue

        try:
            stats = os.statvfs(resolved)
        except OSError as exc:
            lines.append(
                f"⚠ {threshold.label}: unable to inspect {resolved}: {exc}."
            )
            continue

        total = stats.f_files
        free = stats.f_favail if stats.f_favail > 0 else stats.f_ffree
        if total <= 0:
            lines.append(
                f"⚠ {threshold.label}: reported zero inode capacity at {resolved}; verify filesystem."
            )
            continue

        free_ratio = free / total
        percent_text = _format_percent(free_ratio)
        summary = (
            f"{threshold.label}: {free:,} free inodes ({percent_text}) of {total:,} at {resolved}."
        )

        below_count = free < threshold.min_free_inodes
        below_percent = free_ratio < threshold.min_free_percent

        if below_count or below_percent:
            requirements: List[str] = []
            if below_count:
                requirements.append(f"{threshold.min_free_inodes:,} free inodes")
            if below_percent:
                requirements.append(_format_percent(threshold.min_free_percent))
            requirement_text = " and ".join(requirements)
            lines.append(
                f"⚠ {summary} Maintain at least {requirement_text} to avoid inode exhaustion."
            )
        else:
            lines.append(
                f"{summary} Above minimum thresholds ({threshold.min_free_inodes:,} inodes and"
                f" {_format_percent(threshold.min_free_percent)} free)."
            )

    if not lines:
        return ["No inode capacity targets evaluated."]
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


def analyze_network_io_monitor() -> List[str]:
    """Summarize network I/O logging coverage, freshness, and scheduling."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    now = datetime.now(timezone.utc)

    rsyslog_path = NETWORK_IO_RSYSLOG_CONF
    if not rsyslog_path.exists():
        warn(f"Network I/O rsyslog rules missing — {rsyslog_path}.")
    elif not rsyslog_path.is_file():
        warn(f"Network I/O rsyslog configuration {rsyslog_path} is not a regular file.")
    else:
        try:
            contents = rsyslog_path.read_text(encoding="utf-8")
        except OSError as exc:
            warn(f"Unable to read network I/O rsyslog configuration {rsyslog_path}: {exc}.")
        else:
            missing: List[Tuple[str, Path]] = []
            for label, log_path, prefix in NETWORK_IO_LOGS:
                if prefix not in contents or str(log_path) not in contents:
                    missing.append((label, log_path))
            if missing:
                for label, log_path in missing:
                    warn(
                        f"Network I/O rsyslog rules missing {label.lower()} mapping to {log_path};"
                        f" rerun {NETWORK_IO_SERVICE}."
                    )
            else:
                lines.append(
                    f"Network I/O rsyslog rules route expected prefixes — {rsyslog_path}."
                )

    logrotate_path = NETWORK_IO_LOGROTATE_CONF
    if not logrotate_path.exists():
        warn(f"Network I/O logrotate policy missing — {logrotate_path}.")
    elif not logrotate_path.is_file():
        warn(f"Network I/O logrotate policy {logrotate_path} is not a regular file.")
    else:
        try:
            text = logrotate_path.read_text(encoding="utf-8")
        except OSError as exc:
            warn(f"Unable to read network I/O logrotate policy {logrotate_path}: {exc}.")
        else:
            blocks = _parse_logrotate_blocks(text)
            if not blocks:
                warn(
                    f"Network I/O logrotate policy {logrotate_path} defines no log blocks;"
                    " extend it to include inbound/outbound logs."
                )
            else:
                for label, log_path, prefix in NETWORK_IO_LOGS:
                    matched_pattern: Optional[str] = None
                    block_lines: List[str] = []
                    for pattern, candidate_lines in blocks:
                        if fnmatch.fnmatch(str(log_path), pattern):
                            matched_pattern = pattern
                            block_lines = candidate_lines
                            break
                    if matched_pattern is None:
                        warn(
                            f"{label} log {log_path} missing from {logrotate_path}; extend rotation coverage."
                        )
                        continue

                    directives: Dict[str, str] = {}
                    for entry in block_lines:
                        if not entry or entry.startswith("#"):
                            continue
                        key = entry.split()[0].lower()
                        directives.setdefault(key, entry)

                    directive_issues: List[str] = []
                    for required in ("daily", "rotate", "missingok", "notifempty", "compress", "delaycompress"):
                        if required not in directives:
                            directive_issues.append(f"missing {required}")

                    rotate_line = directives.get("rotate")
                    if rotate_line:
                        parts = rotate_line.split()
                        if len(parts) < 2:
                            directive_issues.append("rotate missing count")
                        else:
                            try:
                                if int(parts[1]) < 3:
                                    directive_issues.append(f"rotate {parts[1]} too low")
                            except ValueError:
                                directive_issues.append(f"rotate '{parts[1]}' invalid")
                    else:
                        directive_issues.append("rotate directive absent")

                    create_line = directives.get("create")
                    create_note: Optional[str] = None
                    if create_line:
                        parts = create_line.split()
                        if len(parts) < 4:
                            directive_issues.append("create incomplete")
                        else:
                            mode_token, owner, group = parts[1:4]
                            create_note = f"create {mode_token} {owner}:{group}"
                            try:
                                mode_value = int(mode_token, 8)
                                if mode_value & stat.S_IWOTH:
                                    directive_issues.append(f"mode {mode_token} world-writable")
                                if mode_value & stat.S_IWGRP:
                                    directive_issues.append(f"mode {mode_token} group-writable")
                                if mode_value & (stat.S_IROTH | stat.S_IXOTH):
                                    directive_issues.append(f"mode {mode_token} world-accessible")
                            except ValueError:
                                directive_issues.append(f"mode '{mode_token}' invalid")
                            if owner != "root":
                                directive_issues.append(f"owner {owner}")
                            if group not in SECURE_LOG_GROUPS:
                                directive_issues.append(f"group {group}")
                    else:
                        directive_issues.append("create directive absent")

                    su_line = directives.get("su")
                    su_note: Optional[str] = None
                    if su_line:
                        parts = su_line.split()
                        if len(parts) < 3:
                            directive_issues.append("su incomplete")
                        else:
                            su_user, su_group = parts[1:3]
                            su_note = f"su {su_user}:{su_group}"
                            if su_user != LOGROTATE_SECURE_USER:
                                directive_issues.append(f"su user {su_user}")
                            if su_group not in SECURE_LOG_GROUPS:
                                directive_issues.append(f"su group {su_group}")
                    else:
                        directive_issues.append("su directive absent")

                    if directive_issues:
                        warn(
                            f"{label} log rotation via {matched_pattern} has issues: "
                            + ", ".join(directive_issues)
                        )
                    else:
                        summary_bits = ["daily", "rotate", create_note, su_note]
                        summary = ", ".join(bit for bit in summary_bits if bit)
                        lines.append(
                            f"{label} log rotates securely via {matched_pattern} ({summary})."
                        )

    for label, log_path, prefix in NETWORK_IO_LOGS:
        if not log_path.exists():
            warn(f"{label} log missing — {log_path}.")
            continue
        if not log_path.is_file():
            warn(f"{label} log {log_path} is not a regular file.")
            continue

        try:
            metadata = log_path.stat()
        except OSError as exc:
            warn(f"Unable to stat {label.lower()} log {log_path}: {exc}.")
            continue

        mtime = datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
        skew = mtime - now
        if skew > NETWORK_IO_CLOCK_SKEW:
            warn(
                f"{label} log timestamp {mtime.isoformat()} leads system time by"
                f" {_format_duration(skew)}; verify clock sync."
            )
            continue

        age = now - mtime
        lines.append(f"{label} log updated {_format_duration(age)} ago — {log_path}.")
        if age > NETWORK_IO_STALE_THRESHOLD:
            warn(
                f"{label} log older than {_format_duration(NETWORK_IO_STALE_THRESHOLD)};"
                " ensure iptables logging remains active."
            )

        if metadata.st_size == 0:
            warn(f"{label} log empty; confirm rsyslog is writing entries.")
            continue

        tail_lines, error = _read_tail_lines(log_path, max_bytes=4096)
        if error:
            warn(error)
            continue
        if tail_lines:
            recent = tail_lines[-20:]
            if not any(prefix.strip() in line for line in recent):
                warn(
                    f"{label} log tail lacks expected '{prefix.strip()}' prefix;"
                    " check rsyslog filters."
                )

    if shutil.which("systemctl"):
        info = _query_unit_state(NETWORK_IO_SERVICE)
        if info is None:
            warn(
                "Unable to query network_io_monitor.service; systemctl show returned no data."
            )
        else:
            status_text = _format_unit_status(info)
            lines.append(f"Service status: {status_text}.")
            load_state = (info.load_state or "").lower()
            unit_file_state = (info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({info.detail})" if info.detail else ""
                warn(
                    f"Network I/O monitor service load state {load_state or 'unknown'}{detail};"
                    " reinstall or unmask the unit."
                )
            elif (info.active_state or "").lower() == "failed":
                warn(
                    "Network I/O monitor service failed; inspect journalctl -u"
                    f" {NETWORK_IO_SERVICE}."
                )
            enable_state = _enablement_from_systemctl(NETWORK_IO_SERVICE)
            normalized = enable_state.lower()
            if (
                normalized not in ENABLEMENT_OK_STATES
                and normalized not in ENABLEMENT_ACCEPTABLE_STATES
            ):
                warn(
                    f"Network I/O monitor service enablement {enable_state}; run systemctl enable --now"
                    f" {NETWORK_IO_SERVICE}."
                )
            else:
                lines.append(f"Enablement: {enable_state}.")

    if not issues:
        lines.append("Network I/O monitor logging healthy and current.")

    return lines


def analyze_internet_access_monitor() -> List[str]:
    """Summarize internet connectivity monitoring and scheduling."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    now = datetime.now(timezone.utc)
    log_path = INTERNET_ACCESS_LOG

    if not log_path.exists():
        warn(f"Internet access log missing — {log_path}.")
    elif not log_path.is_file():
        warn(f"Internet access log {log_path} is not a regular file.")
    else:
        try:
            stat_result = log_path.stat()
        except OSError as exc:
            warn(f"Unable to stat internet access log {log_path}: {exc}.")
        else:
            mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            skew = mtime - now
            if skew > INTERNET_ACCESS_CLOCK_SKEW:
                warn(
                    f"Internet access log timestamp {mtime.isoformat()} leads system time by"
                    f" {_format_duration(skew)}; verify clock synchronization."
                )
            else:
                age = now - mtime
                lines.append(
                    f"Internet access log updated {_format_duration(age)} ago — {log_path}."
                )
                if age > INTERNET_ACCESS_STALE_THRESHOLD:
                    warn(
                        "Internet access log older than"
                        f" {_format_duration(INTERNET_ACCESS_STALE_THRESHOLD)}; ensure"
                        f" {INTERNET_ACCESS_TIMER} is active."
                    )

            if stat_result.st_size == 0:
                warn("Internet access log empty; ensure internet_access_monitor.sh is writing events.")
            else:
                tail_lines, error = _read_tail_lines(log_path, max_bytes=4096)
                if error:
                    warn(error)
                else:
                    last_success: Optional[str] = None
                    restart_entry: Optional[str] = None
                    for raw_line in reversed(tail_lines):
                        stripped = raw_line.strip()
                        if not stripped:
                            continue
                        lowered = stripped.lower()
                        if any(marker in lowered for marker in INTERNET_ACCESS_SUCCESS_MARKERS):
                            last_success = stripped
                            break
                        if restart_entry is None and "network restart attempted" in lowered:
                            restart_entry = stripped

                    if last_success:
                        lines.append(f"Latest connectivity entry: {last_success}")
                    elif restart_entry:
                        warn(
                            f"Latest connectivity entry indicates restart attempt: {restart_entry}."
                            " Investigate network health."
                        )
                    else:
                        warn(
                            f"Internet access log tail lacks connectivity verification entries;"
                            f" inspect {INTERNET_ACCESS_SERVICE}."
                        )

    if shutil.which("systemctl"):
        service_info = _query_unit_state(INTERNET_ACCESS_SERVICE)
        if service_info is None:
            warn(
                "Unable to query internet_access_monitor.service; systemctl show returned no data."
            )
        else:
            status_text = _format_unit_status(service_info)
            lines.append(f"Service status: {status_text}.")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                warn(
                    "Internet access monitor service load state"
                    f" {load_state or 'unknown'}{detail}; reinstall or unmask the unit."
                )
            elif (service_info.active_state or "").lower() == "failed":
                warn(
                    "Internet access monitor service failed; inspect journalctl -u"
                    f" {INTERNET_ACCESS_SERVICE}."
                )

            enable_state = _enablement_from_systemctl(INTERNET_ACCESS_SERVICE)
            normalized = enable_state.lower()
            if (
                normalized not in ENABLEMENT_OK_STATES
                and normalized not in ENABLEMENT_ACCEPTABLE_STATES
            ):
                warn(
                    "Internet access monitor service enablement"
                    f" {enable_state}; run systemctl enable --now {INTERNET_ACCESS_SERVICE}."
                )
            else:
                lines.append(f"Service enablement: {enable_state}.")

        timer_info = _query_unit_state(
            INTERNET_ACCESS_TIMER,
            ("OnCalendar", "LastTriggerUSec", "NextElapseUSecRealtime"),
        )
        if timer_info is None:
            warn(
                "Unable to query internet_access_monitor.timer; systemctl show returned no data."
            )
        else:
            status_text = _format_unit_status(timer_info)
            lines.append(f"Timer status: {status_text}.")
            properties = timer_info.properties or {}
            schedule = properties.get("OnCalendar", "")
            if schedule:
                lines.append(f"Timer schedule: {schedule}.")
            else:
                warn("Internet access monitor timer missing OnCalendar schedule; inspect the unit.")

            active_state = (timer_info.active_state or "").lower()
            enable_state = _enablement_from_systemctl(INTERNET_ACCESS_TIMER)
            normalized = enable_state.lower()
            if active_state in {"active", "activating"}:
                if (
                    normalized not in ENABLEMENT_OK_STATES
                    and normalized not in ENABLEMENT_ACCEPTABLE_STATES
                ):
                    warn(
                        "Internet access monitor timer enablement"
                        f" {enable_state}; run systemctl enable --now {INTERNET_ACCESS_TIMER}."
                    )
                else:
                    lines.append(f"Timer enablement: {enable_state}.")
            else:
                warn(
                    f"Internet access monitor timer {status_text}; run systemctl enable --now"
                    f" {INTERNET_ACCESS_TIMER}."
                )

            last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
            if last_trigger is None:
                warn(
                    f"Internet access monitor timer has not triggered yet; run systemctl start"
                    f" {INTERNET_ACCESS_TIMER}."
                )
            else:
                skew = last_trigger - now
                if skew > INTERNET_ACCESS_CLOCK_SKEW:
                    warn(
                        f"Internet access monitor timer last trigger {last_trigger.isoformat()}"
                        f" leads system time by {_format_duration(skew)}; verify NTP."
                    )
                else:
                    age = now - last_trigger
                    lines.append(
                        f"Timer last triggered {_format_duration(age)} ago."
                    )
                    if age > INTERNET_ACCESS_STALE_THRESHOLD + INTERNET_ACCESS_TIMER_GRACE:
                        warn(
                            "Internet access monitor timer last trigger exceeds the five-minute cadence;"
                            " investigate scheduling."
                        )

            next_trigger = _parse_systemd_timestamp(
                properties.get("NextElapseUSecRealtime", "")
            )
            if next_trigger is None:
                warn(
                    "Internet access monitor timer next run unknown; verify the unit configuration."
                )
            else:
                delta = next_trigger - now
                if delta < -INTERNET_ACCESS_CLOCK_SKEW:
                    warn(
                        "Internet access monitor timer next run is in the past; restart the timer."
                    )
                else:
                    lines.append(
                        f"Timer next run in {_format_duration(delta)}."
                    )
                    if delta > INTERNET_ACCESS_TIMER_INTERVAL + INTERNET_ACCESS_TIMER_GRACE:
                        warn(
                            "Internet access monitor timer next run exceeds the five-minute cadence;"
                            " adjust OnUnitActiveSec."
                        )

    if not issues:
        lines.append("Internet access monitoring healthy and current.")

    return lines


def analyze_alert_reporting() -> List[str]:
    """Summarize hourly alert reporting state, logs, and scheduling."""

    config_path, config, _, config_errors = detect_config_with_diagnostics()
    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    for detail in config_errors:
        warn(detail)

    if config_path is None:
        warn("Unable to locate nn_ids.conf; alert reporting automation status is unknown.")
        return lines

    toggle = config.get("NN_IDS_NOTIFY")
    if toggle not in {"0", "1"}:
        warn("NN_IDS_NOTIFY missing or invalid in nn_ids.conf; expected 0 or 1.")
        return lines

    if toggle == "0":
        lines.append(
            "Notifications disabled via NN_IDS_NOTIFY; enable the toggle to generate hourly alert summaries."
        )
        return lines

    now = datetime.now(timezone.utc)
    source_log = ALERT_REPORT_SOURCE_LOG
    state_path = ALERT_REPORT_STATE
    report_log = ALERT_REPORT_LOG

    source_size: Optional[int] = None

    if not source_log.exists():
        warn(f"Alert source log missing — {source_log}.")
    elif not source_log.is_file():
        warn(f"Alert source log {source_log} is not a regular file.")
    else:
        try:
            stat_result = source_log.stat()
        except OSError as exc:
            warn(f"Unable to stat alert source log {source_log}: {exc}.")
        else:
            source_size = stat_result.st_size
            age = now - datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            lines.append(
                f"Alert source log updated {_format_duration(age)} ago"
                f" ({_format_bytes(source_size)} at {source_log})."
            )
            if age > ALERT_REPORT_STALE_THRESHOLD:
                warn(
                    "Alert source log older than"
                    f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)}; confirm nn_ids_capture.service is emitting alerts."
                )

    state_payload: Optional[Dict[str, Any]] = None
    state_cursor: Optional[int] = None
    state_age: Optional[timedelta] = None

    if not state_path.exists():
        warn(f"Alert report state missing — {state_path}.")
    elif not state_path.is_file():
        warn(f"Alert report state {state_path} is not a regular file.")
    else:
        try:
            raw = state_path.read_text(encoding="utf-8")
        except OSError as exc:
            warn(f"Unable to read alert report state {state_path}: {exc}.")
        else:
            try:
                state_payload = json.loads(raw or "{}")
            except json.JSONDecodeError as exc:
                warn(f"Alert report state contains invalid JSON: {exc}.")
            else:
                if not isinstance(state_payload, dict):
                    warn("Alert report state must be a JSON object containing 'pos'.")
                    state_payload = None

        try:
            stat_result = state_path.stat()
        except OSError as exc:
            warn(f"Unable to stat alert report state {state_path}: {exc}.")
        else:
            mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            skew = mtime - now
            if skew > ALERT_REPORT_CLOCK_SKEW:
                warn(
                    f"Alert report state timestamp {mtime.isoformat()} leads system time by"
                    f" {_format_duration(skew)}; verify clock synchronization."
                )
            else:
                state_age = now - mtime
                lines.append(
                    f"Alert report state updated {_format_duration(state_age)} ago — {state_path}."
                )
                if state_age > ALERT_REPORT_STALE_THRESHOLD:
                    warn(
                        "Alert report state older than"
                        f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)}; ensure {ALERT_REPORT_TIMER} is running."
                    )

            permissions = stat.S_IMODE(stat_result.st_mode)
            owner = _describe_owner(stat_result.st_uid, stat_result.st_gid)
            mode_text = _format_mode(stat_result.st_mode)
            state_warnings: List[str] = []
            if stat.S_ISLNK(stat_result.st_mode):
                state_warnings.append("symbolic link")
            if permissions & stat.S_IWOTH:
                state_warnings.append("world-writable")
            try:
                group = grp.getgrgid(stat_result.st_gid).gr_name
            except KeyError:
                group = str(stat_result.st_gid)
            if permissions & stat.S_IWGRP and group not in SECURE_LOG_GROUPS:
                state_warnings.append(f"group-writable ({group})")
            if state_warnings:
                warn(
                    f"Alert report state permissions risky ({owner} {mode_text}; {', '.join(state_warnings)})."
                )
            else:
                lines.append(f"Alert report state secure ({owner} {mode_text}).")

    if state_payload is not None:
        cursor_raw = state_payload.get("pos")
        if isinstance(cursor_raw, bool) or not isinstance(cursor_raw, (int, float)):
            warn(
                f"Alert report state 'pos' expected integer bytes processed; observed {type(cursor_raw).__name__}."
            )
        else:
            state_cursor = int(cursor_raw)
            if state_cursor < 0:
                warn("Alert report state 'pos' negative; rerun nn_ids_report.service to refresh it.")
            else:
                summary = f"State cursor {state_cursor} bytes consumed"
                if source_size is not None and state_cursor > source_size:
                    delta = state_cursor - source_size
                    warn(
                        "Alert report state cursor exceeds source log size by"
                        f" {_format_bytes(delta)}; log rotation bookkeeping may be stale."
                    )
                lines.append(summary + ".")

    parsed_entries: List[Tuple[datetime, str, int]] = []

    if not report_log.exists():
        warn(f"Alert report log missing — {report_log}.")
    elif not report_log.is_file():
        warn(f"Alert report log {report_log} is not a regular file.")
    else:
        try:
            stat_result = report_log.stat()
        except OSError as exc:
            warn(f"Unable to stat alert report log {report_log}: {exc}.")
        else:
            mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            skew = mtime - now
            if skew > ALERT_REPORT_CLOCK_SKEW:
                warn(
                    f"Alert report log timestamp {mtime.isoformat()} leads system time by"
                    f" {_format_duration(skew)}; verify NTP."
                )
            else:
                log_age = now - mtime
                lines.append(
                    f"Alert report log updated {_format_duration(log_age)} ago — {report_log}."
                )
                if log_age > ALERT_REPORT_STALE_THRESHOLD:
                    warn(
                        "Alert report log entries older than"
                        f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)};"
                        f" confirm summaries are still being generated."
                    )

        tail_lines, error = _read_tail_lines(report_log, max_bytes=4096)
        if error:
            warn(error)
        else:
            malformed = 0
            for raw_line in tail_lines:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if len(parts) < 3:
                    malformed += 1
                    continue
                timestamp = _parse_timestamp(parts[0])
                if timestamp is None:
                    malformed += 1
                    continue
                ip_token = parts[1]
                try:
                    ipaddress.ip_address(ip_token)
                except ValueError:
                    malformed += 1
                    continue
                count_token = parts[2].rstrip(":")
                try:
                    count = int(count_token)
                except ValueError:
                    malformed += 1
                    continue
                if count < 1:
                    malformed += 1
                    continue
                parsed_entries.append((timestamp, ip_token, count))

            if malformed:
                warn(
                    "Alert report log tail contains"
                    f" {malformed} malformed entr{'y' if malformed == 1 else 'ies'}; inspect nn_ids_report.py."
                )

    if parsed_entries:
        parsed_entries.sort(key=lambda entry: entry[0])
        latest_time, latest_ip, latest_count = parsed_entries[-1]
        skew = latest_time - now
        if skew > ALERT_REPORT_CLOCK_SKEW:
            warn(
                f"Latest alert report entry {latest_time.isoformat()} leads system time by"
                f" {_format_duration(skew)}; confirm host clocks are synchronized."
            )
        else:
            latest_age = now - latest_time
            lines.append(
                f"Latest alert summary {_format_duration(latest_age)} ago: {latest_ip} ×{latest_count}."
            )
            if latest_age > ALERT_REPORT_STALE_THRESHOLD:
                warn(
                    "Latest alert summary older than"
                    f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)}; ensure {ALERT_REPORT_TIMER} is active."
                )

        unique_ips = len({entry[1] for entry in parsed_entries})
        total_events = sum(entry[2] for entry in parsed_entries)
        lines.append(
            f"Recent summaries cover {unique_ips} unique IP{'s' if unique_ips != 1 else ''}"
            f" across {total_events} event{'s' if total_events != 1 else ''}."
        )
    else:
        warn("Alert report log tail empty; run nn_ids_report.service after generating test alerts.")

    if shutil.which("systemctl"):
        service_info = _query_unit_state(ALERT_REPORT_SERVICE)
        if service_info is None:
            warn("Unable to query nn_ids_report.service; systemctl show returned no data.")
        else:
            status_text = _format_unit_status(service_info)
            lines.append(f"Service status: {status_text}.")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                warn(
                    f"Alert report service load state {load_state or 'unknown'}{detail}; reinstall or unmask the unit."
                )
            elif (service_info.active_state or "").lower() == "failed":
                warn(
                    "Alert report service failed during its last run; inspect journalctl -u"
                    f" {ALERT_REPORT_SERVICE}."
                )
            enable_state = _enablement_from_systemctl(ALERT_REPORT_SERVICE)
            normalized = enable_state.lower()
            if (
                normalized not in ENABLEMENT_OK_STATES
                and normalized not in ENABLEMENT_ACCEPTABLE_STATES
            ):
                warn(
                    f"Alert report service enablement {enable_state}; run systemctl enable --now {ALERT_REPORT_SERVICE}."
                )
            else:
                lines.append(f"Service enablement: {enable_state}.")

        timer_info = _query_unit_state(
            ALERT_REPORT_TIMER,
            ("OnCalendar", "LastTriggerUSec", "NextElapseUSecRealtime"),
        )
        if timer_info is None:
            warn("Unable to query nn_ids_report.timer; systemctl show returned no data.")
        else:
            status_text = _format_unit_status(timer_info)
            lines.append(f"Timer status: {status_text}.")
            properties = timer_info.properties or {}
            schedule = properties.get("OnCalendar", "")
            if schedule:
                lines.append(f"Timer schedule: {schedule}.")
            else:
                warn("Alert report timer missing OnCalendar schedule; inspect the unit definition.")

            active_state = (timer_info.active_state or "").lower()
            enable_state = _enablement_from_systemctl(ALERT_REPORT_TIMER)
            normalized = enable_state.lower()
            if active_state in {"active", "activating"}:
                if (
                    normalized not in ENABLEMENT_OK_STATES
                    and normalized not in ENABLEMENT_ACCEPTABLE_STATES
                ):
                    warn(
                        f"Alert report timer enablement {enable_state}; run systemctl enable --now {ALERT_REPORT_TIMER}."
                    )
                else:
                    lines.append(f"Timer enablement: {enable_state}.")
            else:
                warn(
                    f"Alert report timer {status_text}; run systemctl enable --now {ALERT_REPORT_TIMER}."
                )

            last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
            if last_trigger is None:
                warn(
                    f"Alert report timer has not triggered yet; run systemctl start {ALERT_REPORT_TIMER}."
                )
            else:
                skew = last_trigger - now
                if skew > ALERT_REPORT_CLOCK_SKEW:
                    warn(
                        f"Alert report timer last trigger {last_trigger.isoformat()} leads system time by"
                        f" {_format_duration(skew)}; verify NTP."
                    )
                else:
                    age = now - last_trigger
                    lines.append(f"Timer last triggered {_format_duration(age)} ago.")
                    if age > ALERT_REPORT_TIMER_INTERVAL + ALERT_REPORT_TIMER_GRACE:
                        warn(
                            "Alert report timer last trigger exceeds the hourly cadence; investigate scheduling."
                        )

            next_trigger = _parse_systemd_timestamp(
                properties.get("NextElapseUSecRealtime", "")
            )
            if next_trigger is None:
                warn("Alert report timer next run unknown; verify the unit configuration.")
            else:
                delta = next_trigger - now
                if delta < -ALERT_REPORT_CLOCK_SKEW:
                    warn("Alert report timer next run is in the past; restart the timer.")
                else:
                    lines.append(f"Timer next run in {_format_duration(delta)}.")
                    if delta > ALERT_REPORT_TIMER_INTERVAL + ALERT_REPORT_TIMER_GRACE:
                        warn(
                            "Alert report timer next run exceeds the hourly cadence; adjust OnCalendar."
                        )

    if not issues:
        lines.append("Alert reporting automation healthy and current.")

    return lines


def analyze_ssh_access_controls() -> List[str]:
    """Summarize SSH access control coverage and firewall enforcement."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    script_path = SSH_ACCESS_SCRIPT
    if not script_path.exists():
        warn(f"SSH access control script missing — {script_path}.")
    elif not script_path.is_file():
        warn(f"SSH access control script {script_path} is not a regular file.")
    else:
        try:
            script_stat = script_path.stat()
        except OSError as exc:
            warn(f"Unable to stat SSH access control script {script_path}: {exc}.")
        else:
            owner_text = _describe_owner(script_stat.st_uid, script_stat.st_gid)
            mode_text = _format_mode(script_stat.st_mode)
            if not script_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                warn(
                    f"SSH access control script {script_path} lacks execute permissions; run chmod +x."
                )
            else:
                lines.append(f"Script executable: {script_path} ({owner_text} {mode_text}).")

    whitelist_path, whitelist_notes = resolve_ssh_access_file(
        SSH_WHITELIST_PATH, SSH_WHITELIST_FALLBACKS
    )
    for note in whitelist_notes:
        warn(note)
    whitelist_networks: List[ipaddress._BaseNetwork] = []
    if whitelist_path is not None:
        try:
            stat_result = whitelist_path.stat()
        except OSError as exc:
            warn(f"Unable to stat SSH whitelist {whitelist_path}: {exc}.")
        else:
            owner_text = _describe_owner(stat_result.st_uid, stat_result.st_gid)
            mode_text = _format_mode(stat_result.st_mode)
            lines.append(f"Whitelist permissions: {owner_text} {mode_text} — {whitelist_path}.")

        networks, invalid, duplicates, ipv6_entries = parse_ssh_access_entries(whitelist_path)
        whitelist_networks = networks
        if invalid:
            warn(
                "SSH whitelist contains invalid entries: "
                + ", ".join(sorted(invalid))
            )
        if duplicates:
            warn(
                "SSH whitelist contains duplicate CIDRs: "
                + ", ".join(sorted(set(duplicates)))
            )
        if ipv6_entries:
            warn(
                "SSH whitelist contains IPv6 entries that iptables IPv4 rules ignore: "
                + ", ".join(sorted(ipv6_entries))
            )
        if networks:
            lines.append(
                f"Whitelist defines {len(networks)} CIDR entr{'y' if len(networks) == 1 else 'ies'} at {whitelist_path}."
            )
        else:
            warn(
                "SSH whitelist empty; ssh_access_control.sh will ACCEPT all SSH clients until populated."
            )
        if any(network.prefixlen == 0 for network in networks):
            warn("SSH whitelist includes 0.0.0.0/0; restrict entries to explicit hosts or CIDRs.")

    blacklist_path, blacklist_notes = resolve_ssh_access_file(
        SSH_BLACKLIST_PATH, SSH_BLACKLIST_FALLBACKS
    )
    for note in blacklist_notes:
        warn(note)
    blacklist_networks: List[ipaddress._BaseNetwork] = []
    if blacklist_path is not None:
        try:
            stat_result = blacklist_path.stat()
        except OSError as exc:
            warn(f"Unable to stat SSH blacklist {blacklist_path}: {exc}.")
        else:
            owner_text = _describe_owner(stat_result.st_uid, stat_result.st_gid)
            mode_text = _format_mode(stat_result.st_mode)
            lines.append(f"Blacklist permissions: {owner_text} {mode_text} — {blacklist_path}.")

        networks, invalid, duplicates, ipv6_entries = parse_ssh_access_entries(blacklist_path)
        blacklist_networks = networks
        if invalid:
            warn(
                "SSH blacklist contains invalid entries: "
                + ", ".join(sorted(invalid))
            )
        if duplicates:
            warn(
                "SSH blacklist contains duplicate CIDRs: "
                + ", ".join(sorted(set(duplicates)))
            )
        if ipv6_entries:
            warn(
                "SSH blacklist contains IPv6 entries that iptables IPv4 rules ignore: "
                + ", ".join(sorted(ipv6_entries))
            )
        if networks:
            lines.append(
                f"Blacklist defines {len(networks)} CIDR entr{'y' if len(networks) == 1 else 'ies'} at {blacklist_path}."
            )
        if any(network.prefixlen == 0 for network in networks):
            warn("SSH blacklist includes 0.0.0.0/0; remove blanket drops to avoid locking operators out.")

    if whitelist_networks and blacklist_networks:
        overlaps: List[str] = []
        for allow in whitelist_networks:
            for deny in blacklist_networks:
                if allow.overlaps(deny):
                    overlaps.append(f"{allow} vs {deny}")
        if overlaps:
            warn(
                "SSH whitelist and blacklist overlap: "
                + ", ".join(sorted(set(overlaps)))
            )

    chain_lines, chain_error = _query_iptables_lines(["-S", SSH_CHAIN_NAME])
    if chain_lines is None:
        warn(
            f"Unable to query iptables chain {SSH_CHAIN_NAME}: {chain_error or 'unknown error'}."
        )
    else:
        rule_lines = [line for line in chain_lines if line.startswith("-A ")]
        if not rule_lines:
            warn(
                f"iptables chain {SSH_CHAIN_NAME} has no rules; run ssh_access_control.sh to apply policies."
            )
        else:
            lines.append(
                f"iptables chain {SSH_CHAIN_NAME} includes {len(rule_lines)} rule"
                f"{'s' if len(rule_lines) != 1 else ''}."
            )
            if whitelist_networks:
                drop_present = any(
                    line.startswith(f"-A {SSH_CHAIN_NAME}") and line.endswith("-j DROP")
                    for line in rule_lines
                )
                if not drop_present:
                    warn(
                        f"Whitelist populated but {SSH_CHAIN_NAME} lacks a terminating DROP rule; rerun ssh_access_control.sh."
                    )

    input_lines, input_error = _query_iptables_lines(["-S", "INPUT"])
    if input_lines is None:
        warn(
            "Unable to inspect iptables INPUT chain for SSH enforcement: "
            + (input_error or "unknown error")
        )
    else:
        hook_found = any(
            line.startswith("-A INPUT")
            and "--dport 22" in line
            and f"-j {SSH_CHAIN_NAME}" in line
            for line in input_lines
        )
        if not hook_found:
            warn(
                f"INPUT chain missing jump to {SSH_CHAIN_NAME} for port 22; run ssh_access_control.sh."
            )
        else:
            lines.append(f"INPUT chain routes SSH traffic to {SSH_CHAIN_NAME}.")

    if not issues:
        lines.append("SSH access control automation validated.")

    return lines


def analyze_anti_wipe_monitor() -> List[str]:
    """Summarize anti-wipe monitoring coverage and readiness."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    script_path = ANTI_WIPE_SCRIPT
    if not script_path.exists():
        warn(f"Anti-wipe monitor script missing — {script_path}.")
    elif not script_path.is_file():
        warn(f"Anti-wipe monitor script {script_path} is not a regular file.")
    else:
        try:
            script_stat = script_path.stat()
        except OSError as exc:
            warn(f"Unable to stat anti-wipe monitor script {script_path}: {exc}.")
        else:
            owner_text = _describe_owner(script_stat.st_uid, script_stat.st_gid)
            mode_text = _format_mode(script_stat.st_mode)
            if not script_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                warn(
                    f"Anti-wipe monitor script {script_path} lacks execute permissions; run chmod +x."
                )
            else:
                lines.append(
                    f"Script executable: {script_path} ({owner_text} {mode_text})."
                )

    if shutil.which("inotifywait"):
        lines.append("inotifywait available for directory monitoring.")
    else:
        warn("inotifywait binary missing; install inotify-tools to enable anti-wipe monitoring.")

    log_path = ANTI_WIPE_LOG
    if not log_path.exists():
        warn(f"Anti-wipe monitor log missing — {log_path}.")
    elif not log_path.is_file():
        warn(f"Anti-wipe monitor log {log_path} is not a regular file.")
    else:
        try:
            stat_result = log_path.stat()
        except OSError as exc:
            warn(f"Unable to stat anti-wipe monitor log {log_path}: {exc}.")
        else:
            lines.append(
                f"Anti-wipe monitor log size {stat_result.st_size} bytes — {log_path}."
            )
            tail_lines, error = _read_tail_lines(log_path, max_bytes=2048)
            if error:
                warn(error)
            else:
                entry = next((line.strip() for line in reversed(tail_lines) if line.strip()), "")
                if entry:
                    lines.append(f"Latest anti-wipe entry: {entry}")
                else:
                    lines.append("No anti-wipe activity recorded yet.")

    if shutil.which("systemctl"):
        service_info = _query_unit_state(ANTI_WIPE_SERVICE)
        if service_info is None:
            warn("Unable to query anti_wipe_monitor.service; systemctl show returned no data.")
        else:
            status_text = _format_unit_status(service_info)
            lines.append(f"Service status: {status_text}.")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                warn(
                    "Anti-wipe monitor service load state"
                    f" {load_state or 'unknown'}{detail}; reinstall or unmask the unit."
                )
            elif (service_info.active_state or "").lower() == "failed":
                warn(
                    "Anti-wipe monitor service failed; inspect journalctl -u"
                    f" {ANTI_WIPE_SERVICE}."
                )

            enable_state = _enablement_from_systemctl(ANTI_WIPE_SERVICE)
            normalized = enable_state.lower()
            if (
                normalized not in ENABLEMENT_OK_STATES
                and normalized not in ENABLEMENT_ACCEPTABLE_STATES
            ):
                warn(
                    "Anti-wipe monitor service enablement"
                    f" {enable_state}; run systemctl enable --now {ANTI_WIPE_SERVICE}."
                )
            else:
                lines.append(f"Service enablement: {enable_state}.")

    if not issues:
        lines.append("Anti-wipe monitoring deployed and ready.")

    return lines


def analyze_resource_monitor_log() -> List[str]:
    """Summarize resource monitor activity and scheduling."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    log_path = RESOURCE_MONITOR_LOG
    if not log_path.exists():
        warn(f"Resource monitor log missing — {log_path}.")
        return lines
    if not log_path.is_file():
        warn(f"Resource monitor log {log_path} is not a regular file.")
        return lines

    try:
        stat_result = log_path.stat()
    except OSError as exc:
        warn(f"Unable to stat resource monitor log {log_path}: {exc}.")
        return lines

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
        warn(
            f"Resource monitor log timestamp {mtime.isoformat()} leads system time by"
            f" {_format_duration(skew)}; verify clock synchronization."
        )
    age = now - mtime
    lines.append(
        f"Resource monitor log updated {_format_duration(age)} ago — {log_path}"
    )
    if age > RESOURCE_MONITOR_STALE_THRESHOLD:
        warn(
            f"Resource monitor log update overdue; ensure {RESOURCE_MONITOR_TIMER} is running."
        )

    tail_lines, error = _read_tail_lines(log_path)
    if error:
        warn(error)
        return lines

    parsed_entries: List[Tuple[datetime, str]] = []
    malformed = 0

    for raw_line in tail_lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        parts = stripped.split(" ", 1)
        if len(parts) < 2:
            malformed += 1
            continue
        timestamp = _parse_iso_timestamp(parts[0])
        if timestamp is None:
            malformed += 1
            continue
        parsed_entries.append((timestamp, parts[1].strip()))

    if malformed:
        warn(
            f"Resource monitor log tail contains {malformed} malformed entries;"
            " refresh nn_ids_resource_monitor logging."
        )

    if not parsed_entries:
        warn(
            "Resource monitor log tail empty; ensure nn_ids_resource_monitor.service is invoked by the timer."
        )
        return lines

    latest_time, latest_message = parsed_entries[-1]
    skew = latest_time - now
    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
        warn(
            f"Latest resource monitor entry {latest_time.isoformat()} leads system time by"
            f" {_format_duration(skew)}; verify NTP alignment."
        )
    else:
        age = now - latest_time
        if age > RESOURCE_MONITOR_STALE_THRESHOLD:
            warn(
                "Latest resource monitor entry stale; ensure the timer triggered recently."
            )
        else:
            lines.append(
                f"Latest entry {_format_duration(age)} ago: {latest_message}"
            )

    missing_events = [
        entry_time for entry_time, message in parsed_entries if "process not found" in message.lower()
    ]
    if missing_events:
        last_missing = missing_events[-1]
        warn(
            f"Resource monitor logged {len(missing_events)} missing nn_ids.service events;"
            f" most recent {_format_duration(now - last_missing)} ago."
        )

    spike_events = [
        entry_time for entry_time, message in parsed_entries if message.lower().startswith("resource spike")
    ]
    if spike_events:
        recent_spikes = [
            entry_time for entry_time in spike_events if now - entry_time <= RESOURCE_MONITOR_SPIKE_WINDOW
        ]
        if recent_spikes:
            lines.append(
                f"Resource monitor observed {len(recent_spikes)} spike"
                f"{'s' if len(recent_spikes) != 1 else ''} in the last"
                f" {_format_duration(RESOURCE_MONITOR_SPIKE_WINDOW)}."
            )
            if len(recent_spikes) >= RESOURCE_MONITOR_SPIKE_ALERT_COUNT:
                warn("Resource spikes exceed tolerance; investigate CPU and memory consumption.")

    if shutil.which("systemctl"):
        service_info = _query_unit_state(RESOURCE_MONITOR_SERVICE)
        if service_info is None:
            warn(
                "Unable to query resource monitor service; systemctl show returned no data."
            )
        else:
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            status_text = _format_unit_status(service_info)
            lines.append(f"Service status: {status_text}.")
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                warn(
                    f"Resource monitor service load state {load_state or 'unknown'}{detail};"
                    " reinstall or unmask the unit."
                )
            elif (service_info.active_state or "").lower() == "failed":
                warn(
                    "Resource monitor service failed on last run; inspect journalctl -u"
                    f" {RESOURCE_MONITOR_SERVICE}."
                )

        timer_info = _query_unit_state(
            RESOURCE_MONITOR_TIMER,
            (
                "LastTriggerUSec",
                "NextElapseUSecRealtime",
                "OnCalendar",
                "TimersCalendar",
            ),
        )
        if timer_info is None:
            warn(
                "Unable to query resource monitor timer; systemctl show returned no data."
            )
        else:
            load_state = (timer_info.load_state or "").lower()
            unit_file_state = (timer_info.unit_file_state or "").lower()
            status_text = _format_unit_status(timer_info)
            lines.append(f"Timer status: {status_text}.")
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({timer_info.detail})" if timer_info.detail else ""
                warn(
                    f"Resource monitor timer load state {load_state or 'unknown'}{detail};"
                    " reinstall or unmask the unit."
                )
            else:
                enable_state = _enablement_from_systemctl(RESOURCE_MONITOR_TIMER)
                if enable_state not in ENABLEMENT_OK_STATES and enable_state not in ENABLEMENT_ACCEPTABLE_STATES:
                    warn(
                        f"Resource monitor timer enablement {enable_state}; run systemctl enable --now"
                        f" {RESOURCE_MONITOR_TIMER}."
                    )

                schedule_raw = (
                    (timer_info.properties or {}).get("OnCalendar")
                    or (timer_info.properties or {}).get("TimersCalendar")
                    or ""
                )
                schedule_clean = " ".join(schedule_raw.split())
                if schedule_clean and schedule_clean.lower() != "n/a":
                    lines.append(f"Timer schedule: {schedule_clean}.")
                else:
                    warn("Resource monitor timer OnCalendar schedule unavailable; inspect the unit file.")

                last_trigger = _parse_systemd_timestamp(
                    (timer_info.properties or {}).get("LastTriggerUSec", "")
                )
                if last_trigger is None:
                    warn(
                        f"Resource monitor timer has not triggered yet; run systemctl start {RESOURCE_MONITOR_TIMER}."
                    )
                else:
                    skew = last_trigger - now
                    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
                        warn(
                            f"Timer last trigger {last_trigger.isoformat()} leads system time by"
                            f" {_format_duration(skew)}; verify NTP."
                        )
                    else:
                        age = now - last_trigger
                        lines.append(
                            f"Timer last triggered {_format_duration(age)} ago."
                        )
                        if age > RESOURCE_MONITOR_STALE_THRESHOLD + RESOURCE_MONITOR_TIMER_GRACE:
                            warn(
                                "Timer last trigger exceeds the five-minute cadence; restart the timer."
                            )

                next_trigger = _parse_systemd_timestamp(
                    (timer_info.properties or {}).get("NextElapseUSecRealtime", "")
                )
                if next_trigger is None:
                    warn(
                        f"Resource monitor timer next run unknown; inspect systemctl cat {RESOURCE_MONITOR_TIMER}."
                    )
                else:
                    delta = next_trigger - now
                    if delta < -RESOURCE_MONITOR_CLOCK_SKEW:
                        warn(
                            f"Resource monitor timer next run {next_trigger.isoformat()} is in the past; restart the timer."
                        )
                    else:
                        lines.append(
                            f"Timer next run in {_format_duration(delta)}."
                        )
                        if delta > RESOURCE_MONITOR_TIMER_INTERVAL + RESOURCE_MONITOR_TIMER_GRACE:
                            warn(
                                "Timer next run exceeds the five-minute cadence; adjust OnCalendar."
                            )

    if not issues:
        lines.append("Resource monitor log healthy and scheduling on time.")

    return lines


def analyze_process_monitor_baseline() -> List[str]:
    """Summarize the health of the process monitor baseline and companion logs."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    baseline = PROCESS_MONITOR_BASELINE
    if not baseline.exists():
        warn(f"Process monitor baseline missing — {baseline}.")
        return lines
    if not baseline.is_file():
        warn(f"Process monitor baseline {baseline} is not a regular file.")
        return lines

    try:
        text = baseline.read_text(encoding="utf-8")
    except OSError as exc:
        warn(f"Unable to read process monitor baseline {baseline}: {exc}.")
        return lines

    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        warn(f"Process monitor baseline contains invalid JSON: {exc}.")
        return lines

    if not isinstance(payload, dict):
        warn("Process monitor baseline must be a JSON object containing process and service lists.")
        return lines

    def sanitize_list(value: object, label: str, limit: int) -> List[str]:
        entries: List[str] = []
        if value is None:
            warn(f"Process monitor baseline missing '{label}' list; rerun process_monitor.service.")
            return entries
        if not isinstance(value, list):
            warn(f"Process monitor baseline '{label}' entry must be a list of strings.")
            return entries
        if len(value) > limit:
            warn(f"Process monitor '{label}' list contains {len(value)} entries; trimming may have failed.")
        seen: Set[str] = set()
        duplicates: Set[str] = set()
        for index, item in enumerate(value):
            if not isinstance(item, str):
                warn(
                    f"Process monitor '{label}' entry {index} has invalid type {type(item).__name__}."
                )
                continue
            candidate = item.strip()
            if not candidate:
                warn(f"Process monitor '{label}' entry {index} is empty or whitespace-only.")
                continue
            entries.append(candidate)
            if candidate in seen:
                duplicates.add(candidate)
            seen.add(candidate)
        if duplicates:
            warn(
                f"Process monitor '{label}' list contains duplicates: "
                + ", ".join(sorted(duplicates))
            )
        if entries and entries != sorted(entries):
            warn(f"Process monitor '{label}' list not sorted; baseline serialization may be stale.")
        return entries

    processes = sanitize_list(
        payload.get("processes"), "processes", PROCESS_MONITOR_MAX_PROCESSES
    )
    services = sanitize_list(
        payload.get("services"), "services", PROCESS_MONITOR_MAX_SERVICES
    )

    if not processes:
        warn("Process monitor baseline contains no tracked processes.")
    if not services:
        warn("Process monitor baseline contains no tracked services.")

    try:
        stat_result = baseline.stat()
    except OSError as exc:
        warn(f"Unable to stat process monitor baseline {baseline}: {exc}.")
        return lines

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > PROCESS_MONITOR_CLOCK_SKEW:
        warn(
            f"Process monitor baseline timestamp {mtime.isoformat()} leads system time by"
            f" {_format_duration(skew)}; verify clock sync."
        )
    age = now - mtime
    lines.append(
        f"Process monitor baseline tracks {len(processes)} processes and {len(services)} services;"
        f" updated {_format_duration(age)} ago — {baseline}"
    )
    if age > PROCESS_MONITOR_STALE_THRESHOLD:
        warn("Process monitor baseline update overdue; ensure process_monitor.timer is running.")

    optional_paths = (
        ("Process monitor alert log", PROCESS_MONITOR_ALERT_LOG),
        ("Process monitor activity log", PROCESS_MONITOR_ACTIVITY_LOG),
    )

    for label, path in optional_paths:
        if not path.exists():
            lines.append(f"{label} not present yet — {path}.")
            continue
        if not path.is_file():
            warn(f"{label} {path} is not a regular file.")
            continue
        try:
            metadata = path.stat()
        except OSError as exc:
            warn(f"Unable to stat {label.lower()} {path}: {exc}.")
            continue
        age = now - datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
        lines.append(f"{label} updated {_format_duration(age)} ago — {path}")

    if not issues:
        lines.append("Process monitor baseline healthy and recently refreshed.")

    return lines


def analyze_port_monitor_baseline() -> List[str]:
    """Summarize the health of the port monitor baseline and alert log."""

    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    baseline = PORT_MONITOR_BASELINE
    if not baseline.exists():
        warn(f"Port monitor baseline missing — {baseline}.")
        return lines
    if not baseline.is_file():
        warn(f"Port monitor baseline {baseline} is not a regular file.")
        return lines

    try:
        text = baseline.read_text(encoding="utf-8")
    except OSError as exc:
        warn(f"Unable to read port monitor baseline {baseline}: {exc}.")
        return lines

    try:
        payload = json.loads(text or "[]")
    except json.JSONDecodeError as exc:
        warn(f"Port monitor baseline contains invalid JSON: {exc}.")
        return lines

    if not isinstance(payload, list):
        warn("Port monitor baseline must be a JSON array of listening ports.")
        return lines

    ports: List[int] = []
    seen: Set[int] = set()
    duplicates: Set[int] = set()

    if len(payload) > PORT_MONITOR_MAX_PORTS:
        warn(
            f"Port monitor baseline lists {len(payload)} ports; trimming may have failed."
        )

    for index, entry in enumerate(payload):
        if isinstance(entry, bool) or not isinstance(entry, int):
            warn(
                f"Port monitor baseline entry {index} has invalid type {type(entry).__name__}; expected integer port."
            )
            continue
        if not 1 <= int(entry) <= 65535:
            warn(f"Port monitor baseline entry {index} outside valid port range: {entry}.")
            continue
        value = int(entry)
        ports.append(value)
        if value in seen:
            duplicates.add(value)
        seen.add(value)

    if duplicates:
        warn(
            "Port monitor baseline contains duplicate ports: "
            + ", ".join(str(port) for port in sorted(duplicates))
        )

    if ports and ports != sorted(ports):
        warn("Port monitor baseline not sorted; serialization may be stale.")

    if not ports:
        warn("Port monitor baseline currently tracks no listening ports.")

    try:
        stat_result = baseline.stat()
    except OSError as exc:
        warn(f"Unable to stat port monitor baseline {baseline}: {exc}.")
        return lines

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > PORT_MONITOR_CLOCK_SKEW:
        warn(
            f"Port monitor baseline timestamp {mtime.isoformat()} leads system time by"
            f" {_format_duration(skew)}; verify clock sync."
        )
    age = now - mtime
    lines.append(
        f"Port monitor baseline tracks {len(ports)} listening ports; updated {_format_duration(age)} ago — {baseline}"
    )
    if age > PORT_MONITOR_STALE_THRESHOLD:
        warn("Port monitor baseline update overdue; ensure port_socket_monitor.timer is running.")

    if PORT_MONITOR_ALERT_LOG.exists():
        if not PORT_MONITOR_ALERT_LOG.is_file():
            warn(f"Port monitor alert log {PORT_MONITOR_ALERT_LOG} is not a regular file.")
        else:
            try:
                metadata = PORT_MONITOR_ALERT_LOG.stat()
            except OSError as exc:
                warn(f"Unable to stat port monitor alert log {PORT_MONITOR_ALERT_LOG}: {exc}.")
            else:
                age = now - datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
                lines.append(
                    f"Port monitor alert log updated {_format_duration(age)} ago — {PORT_MONITOR_ALERT_LOG}"
                )
    else:
        lines.append(
            f"Port monitor alert log not present yet — {PORT_MONITOR_ALERT_LOG}."
        )

    if not issues:
        lines.append("Port monitor baseline healthy and recently refreshed.")

    return lines


def analyze_autoblock_state() -> List[str]:
    """Summarize the health of the automatic blocking state file."""

    config_path, config, _, config_errors = detect_config_with_diagnostics()
    lines: List[str] = []
    issues = False

    def warn(message: str) -> None:
        nonlocal issues
        issues = True
        lines.append(f"⚠ {message}")

    for detail in config_errors:
        warn(detail)

    if config_path is None:
        warn("Unable to locate nn_ids.conf; autoblock automation status is unknown.")
        return lines

    toggle = config.get("NN_IDS_AUTOBLOCK")
    if toggle not in {"0", "1"}:
        warn("NN_IDS_AUTOBLOCK missing or invalid in nn_ids.conf; expected 0 or 1.")
        return lines

    if toggle == "0":
        lines.append(
            "Autoblock disabled via NN_IDS_AUTOBLOCK; enable automatic blocking to drop repeated offenders."
        )
        return lines

    state_path = AUTOBLOCK_STATE
    if not state_path.exists():
        warn(f"Autoblock state missing — {state_path}.")
        return lines
    if not state_path.is_file():
        warn(f"Autoblock state {state_path} is not a regular file.")
        return lines

    try:
        text = state_path.read_text(encoding="utf-8")
    except OSError as exc:
        warn(f"Unable to read autoblock state {state_path}: {exc}.")
        return lines

    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        warn(f"Autoblock state contains invalid JSON: {exc}.")
        return lines

    if not isinstance(payload, dict):
        warn("Autoblock state must be a JSON object containing counts, blocked entries, and a log offset.")
        return lines

    counts_raw = payload.get("counts")
    if counts_raw is None:
        warn("Autoblock state missing 'counts' dictionary; rerun nn_ids_autoblock.service.")
        return lines
    if not isinstance(counts_raw, dict):
        warn("Autoblock 'counts' entry must be a dictionary mapping IPs to integers.")
        return lines

    counts: Dict[str, int] = {}
    invalid_ip_keys: List[str] = []
    invalid_value_entries: List[str] = []
    for key, value in counts_raw.items():
        if not isinstance(key, str):
            invalid_ip_keys.append(repr(key))
            continue
        candidate = key.strip()
        if not candidate:
            invalid_ip_keys.append(repr(key))
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            invalid_ip_keys.append(candidate)
        if isinstance(value, bool) or not isinstance(value, int):
            invalid_value_entries.append(f"{candidate} ({type(value).__name__})")
            continue
        if value < 0:
            invalid_value_entries.append(f"{candidate} (negative)")
            continue
        counts[candidate] = int(value)

    if invalid_ip_keys:
        warn(
            "Autoblock counts contain invalid IP keys: "
            + ", ".join(sorted({entry for entry in invalid_ip_keys}))
        )
    if invalid_value_entries:
        warn(
            "Autoblock counts include invalid values: "
            + ", ".join(sorted({entry for entry in invalid_value_entries}))
        )

    blocked_raw = payload.get("blocked")
    if blocked_raw is None:
        warn("Autoblock state missing 'blocked' mapping; rerun nn_ids_autoblock.service.")
        return lines
    if not isinstance(blocked_raw, dict):
        warn("Autoblock 'blocked' entry must map IPs to Unix timestamps.")
        return lines

    now = datetime.now(timezone.utc)
    blocked: Dict[str, datetime] = {}
    stale_blocks: List[str] = []
    future_blocks: List[str] = []

    for key, value in blocked_raw.items():
        if not isinstance(key, str):
            warn(f"Autoblock 'blocked' entry has non-string key {key!r}.")
            continue
        candidate = key.strip()
        if not candidate:
            warn("Autoblock 'blocked' entry contains an empty IP string.")
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            warn(f"Autoblock 'blocked' entry contains invalid IP {candidate}.")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            warn(
                f"Autoblock 'blocked' timestamp for {candidate} has invalid type {type(value).__name__}."
            )
            continue
        timestamp = datetime.fromtimestamp(float(value), timezone.utc)
        skew = timestamp - now
        if skew > AUTOBLOCK_CLOCK_SKEW:
            future_blocks.append(f"{candidate} ({_format_duration(skew)})")
        else:
            age = now - timestamp
            if age > AUTOBLOCK_BLOCK_DURATION + AUTOBLOCK_BLOCK_GRACE:
                stale_blocks.append(f"{candidate} ({_format_duration(age)})")
        blocked[candidate] = timestamp

    if future_blocks:
        warn(
            "Autoblock state recorded future timestamps: "
            + ", ".join(sorted(future_blocks))
            + "; verify system clock synchronisation."
        )

    if stale_blocks:
        warn(
            "Autoblock entries persisted beyond the expected duration: "
            + ", ".join(sorted(stale_blocks))
            + f"; blocks should expire within {_format_duration(AUTOBLOCK_BLOCK_DURATION)}."
        )

    missing_counts = [ip for ip in blocked if ip not in counts]
    if missing_counts:
        warn(
            "Autoblock state missing counts for blocked IPs: "
            + ", ".join(sorted({ip for ip in missing_counts}))
        )

    insufficient_counts = [ip for ip in blocked if counts.get(ip, 0) < AUTOBLOCK_THRESHOLD]
    if insufficient_counts:
        warn(
            "Autoblock state recorded blocks before reaching threshold "
            f"{AUTOBLOCK_THRESHOLD}: " + ", ".join(sorted({ip for ip in insufficient_counts}))
        )

    pos_value = payload.get("pos")
    if pos_value is None:
        warn("Autoblock state missing 'pos' log offset; log tail tracking may be stale.")
    elif isinstance(pos_value, bool) or not isinstance(pos_value, int):
        warn(
            f"Autoblock 'pos' value has invalid type {type(pos_value).__name__}; expected non-negative integer."
        )
    elif pos_value < 0:
        warn("Autoblock 'pos' offset is negative; state file may be corrupt.")

    try:
        stat_result = state_path.stat()
    except OSError as exc:
        warn(f"Unable to stat autoblock state {state_path}: {exc}.")
        return lines

    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > AUTOBLOCK_CLOCK_SKEW:
        warn(
            f"Autoblock state timestamp {mtime.isoformat()} leads system time by {_format_duration(skew)}; verify clock sync."
        )

    age = now - mtime
    summary = (
        f"Autoblock tracks {len(counts)} addresses ({len(blocked)} currently blocked);"
        f" updated {_format_duration(age)} ago — {state_path}"
    )
    lines.append(summary)

    if blocked:
        newest = max(blocked.values())
        oldest = min(blocked.values())
        lines.append(
            f"Active blocks span {_format_duration(now - oldest)} to {_format_duration(now - newest)} ago."
        )

    if age > AUTOBLOCK_STALE_THRESHOLD:
        warn("Autoblock update overdue; ensure nn_ids_autoblock.timer is running.")

    if not issues:
        lines.append("Autoblock state healthy and recently refreshed.")

    return lines


def analyze_threat_feed_blocklist() -> List[str]:
    """Summarize the health of the threat feed blocklist state."""

    config_path, config, _, config_errors = detect_config_with_diagnostics()
    lines: List[str] = []

    if config_errors:
        lines.extend(f"⚠ {issue}" for issue in config_errors)

    endpoints, endpoint_notes = resolve_threat_feed_endpoints(config)
    endpoints_logged = False

    def append_endpoint_diagnostics() -> None:
        nonlocal endpoints_logged
        if endpoints_logged:
            return
        endpoints_logged = True
        for note in endpoint_notes:
            lines.append(f"⚠ {note}")
        if not endpoints:
            lines.append(
                f"⚠ No threat feed endpoints configured; update {THREAT_FEED_ENDPOINT_KEY} or threat_feed_blocklist.py."
            )
            return
        lines.append("Threat feed endpoints:")
        reachable = 0
        for endpoint in endpoints:
            success, detail = probe_threat_feed_endpoint(endpoint)
            indicator = "✓" if success else "⚠"
            lines.append(f"{indicator} {endpoint} — {detail}")
            if success:
                reachable += 1
        if reachable == 0:
            lines.append(
                "⚠ Unable to reach any configured threat feed endpoints; remote feeds may be offline or blocked."
            )

    if config_path is None:
        lines.append(
            "⚠ Unable to locate nn_ids.conf; threat feed automation status is unknown."
        )
        append_endpoint_diagnostics()
        return lines

    toggle = config.get("NN_IDS_THREAT_FEED")
    if toggle not in {"0", "1"}:
        lines.append(
            "⚠ NN_IDS_THREAT_FEED missing or invalid in nn_ids.conf; expected 0 or 1."
        )
        append_endpoint_diagnostics()
        return lines

    if toggle == "0":
        lines.append(
            "Threat feed automation disabled via NN_IDS_THREAT_FEED; enable the toggle to populate the blocklist."
        )
        append_endpoint_diagnostics()
        return lines

    state_path = THREAT_FEED_STATE
    if not state_path.exists():
        lines.append(f"⚠ Threat feed state missing — {state_path}.")
        append_endpoint_diagnostics()
        return lines
    if not state_path.is_file():
        lines.append(f"⚠ Threat feed state {state_path} is not a regular file.")
        append_endpoint_diagnostics()
        return lines

    try:
        text = state_path.read_text(encoding="utf-8")
    except OSError as exc:
        lines.append(f"⚠ Unable to read threat feed state {state_path}: {exc}.")
        append_endpoint_diagnostics()
        return lines

    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        lines.append(f"⚠ Threat feed state contains invalid JSON: {exc}.")
        append_endpoint_diagnostics()
        return lines

    if not isinstance(payload, dict):
        lines.append("⚠ Threat feed state must be a JSON object containing 'blocked'.")
        append_endpoint_diagnostics()
        return lines

    blocked_raw = payload.get("blocked")
    if blocked_raw is None:
        lines.append("⚠ Threat feed state missing 'blocked' list; rerun threat_feed_blocklist.service.")
        append_endpoint_diagnostics()
        return lines
    if not isinstance(blocked_raw, list):
        lines.append("⚠ Threat feed state 'blocked' entry is not a list; refresh the state file.")
        append_endpoint_diagnostics()
        return lines

    valid: List[str] = []
    invalid: List[str] = []
    for entry in blocked_raw:
        if isinstance(entry, str):
            candidate = entry.strip()
            if not candidate:
                invalid.append(repr(entry))
                continue
        else:
            invalid.append(repr(entry))
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            invalid.append(candidate)
        else:
            valid.append(candidate)

    if invalid:
        lines.append(
            "⚠ Blocklist contains invalid addresses: "
            + ", ".join(sorted({value for value in invalid}))
        )

    unique = len(set(valid))
    duplicate_count = len(valid) - unique
    if duplicate_count > 0:
        lines.append(
            f"⚠ Blocklist includes {duplicate_count} duplicate entries; regenerate the state to deduplicate."
        )

    try:
        stat_result = state_path.stat()
    except OSError as exc:
        lines.append(f"⚠ Unable to stat threat feed state {state_path}: {exc}.")
        append_endpoint_diagnostics()
        return lines

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > THREAT_FEED_CLOCK_SKEW:
        lines.append(
            f"⚠ Threat feed state timestamp {mtime.isoformat()} leads system time by {_format_duration(skew)}; verify clock sync."
        )

    age = now - mtime
    summary = (
        f"Blocklist tracks {unique} blocked addresses; updated {_format_duration(age)} ago — {state_path}"
    )
    if unique == 0:
        lines.append(f"⚠ {summary}")
    else:
        lines.append(summary)

    if age > THREAT_FEED_STALE_THRESHOLD:
        lines.append(
            "⚠ Blocklist update overdue; run threat_feed_blocklist.service to refresh remote feeds."
        )

    append_endpoint_diagnostics()

    if not any(line.startswith("⚠") for line in lines):
        lines.append("Threat feed blocklist healthy and recently refreshed.")

    return lines


def _summarize_logrotate_state(
    config_path: Path,
    config_text: str,
    snapshots: Dict[Path, Tuple[bool, Optional[int]]],
) -> List[str]:
    if not snapshots:
        return []

    state_path, candidates = resolve_logrotate_state_path(config_text)
    if state_path is None:
        candidate_text = ", ".join(str(path) for path in candidates) if candidates else "(none)"
        return [
            "⚠ Logrotate state file missing; expected rotation tracking at "
            f"{candidate_text}.",
        ]

    metadata_issues, metadata_summary = _audit_logrotate_state_metadata(state_path)
    lines: List[str] = [f"State file: {state_path}"]
    for issue in metadata_issues:
        suffix = issue if issue.endswith((".", "!", "?")) else f"{issue}."
        lines.append(f"⚠ {suffix}")
    if metadata_summary:
        summary_text = (
            metadata_summary
            if metadata_summary.endswith((".", "!", "?"))
            else f"{metadata_summary}."
        )
        lines.append(summary_text)

    try:
        state_text = state_path.read_text(encoding="utf-8")
    except OSError as exc:
        lines.append(f"⚠ Unable to read logrotate state file {state_path}: {exc}")
        return lines

    entries, warnings = _parse_logrotate_state(state_text)
    lines.extend(warnings)

    now = datetime.now(timezone.utc)

    for log_path, (exists, size) in snapshots.items():
        entry = entries.get(str(log_path)) or entries.get(log_path.as_posix())
        display = log_path.name
        size_value = size or 0
        non_empty = bool(exists and size_value > 0)

        if entry is None:
            if non_empty:
                lines.append(
                    f"⚠ {display}: not tracked in {state_path}; run 'logrotate {config_path}' to register rotations."
                )
            else:
                lines.append(
                    f"⚠ {display}: rotation not yet recorded; execute logrotate once after the log populates."
                )
            continue

        if entry > now + LOGROTATE_STATE_CLOCK_SKEW:
            skew = entry - now
            lines.append(
                f"⚠ {display}: rotation timestamp {entry.isoformat()} is {_format_duration(skew)} ahead of system clock."
            )
            continue

        age = now - entry
        if age > LOGROTATE_ROTATION_STALE and non_empty:
            lines.append(
                f"⚠ {display}: last rotation {_format_duration(age)} ago; ensure logrotate executes daily."
            )
        elif age > LOGROTATE_ROTATION_STALE:
            lines.append(
                f"⚠ {display}: rotation {_format_duration(age)} ago but log empty — confirm schedule."
            )
        else:
            lines.append(f"{display}: last rotation {_format_duration(age)} ago.")

    return lines


def analyze_logrotate_scheduler() -> List[str]:
    """Report how logrotate is scheduled to run automatically."""

    lines: List[str] = []
    timer_ok = False
    cron_ok = False
    schedule_lines: List[str] = []

    systemctl_available = shutil.which("systemctl") is not None

    if systemctl_available:
        timer_info = _query_unit_state(
            LOGROTATE_TIMER_UNIT,
            (
                "LastTriggerUSec",
                "NextElapseUSecRealtime",
                "OnCalendar",
                "TimersCalendar",
            ),
        )
        enable_state = _enablement_from_systemctl(LOGROTATE_TIMER_UNIT).lower()
        status = _format_unit_status(timer_info)
        load_state = timer_info.load_state.lower() if timer_info else "unknown"
        unit_file_state = timer_info.unit_file_state.lower() if timer_info else ""

        if timer_info is None:
            lines.append("⚠ Unable to query logrotate.timer state via systemctl show.")
        elif load_state != "loaded":
            if load_state == "not-found":
                lines.append(
                    "⚠ logrotate.timer missing; reinstall the logrotate package to restore scheduled rotations."
                )
            elif load_state == "masked":
                lines.append("⚠ logrotate.timer masked; run systemctl unmask logrotate.timer.")
            else:
                detail = f" ({timer_info.detail})" if timer_info and timer_info.detail else ""
                lines.append(
                    f"⚠ logrotate.timer load state {load_state or 'unknown'}{detail}; investigate systemd configuration."
                )
        elif unit_file_state == "masked":
            lines.append("⚠ logrotate.timer unit file masked; run systemctl unmask logrotate.timer.")
        else:
            active_state = timer_info.active_state.lower() if timer_info.active_state else ""
            if active_state in {"active", "activating"}:
                if enable_state in ENABLEMENT_OK_STATES or enable_state in ENABLEMENT_ACCEPTABLE_STATES:
                    descriptor = enable_state or "enabled"
                    timer_ok = True
                    lines.append(
                        f"logrotate.timer {status}; systemd will trigger rotations ({descriptor})."
                    )
                else:
                    lines.append(
                        f"⚠ logrotate.timer {status} but not enabled for startup (state: {enable_state or 'disabled'}); "
                        "run systemctl enable --now logrotate.timer."
                    )
            else:
                lines.append(
                    f"⚠ logrotate.timer {status}; start it with systemctl enable --now logrotate.timer."
                )

            if timer_info and load_state == "loaded":
                schedule_lines.extend(
                    _describe_logrotate_timer_schedule(timer_info.properties)
                )

        service_info = _query_unit_state(LOGROTATE_SERVICE_UNIT)
        if service_info is not None:
            service_load = service_info.load_state.lower()
            if service_load == "masked":
                lines.append("⚠ logrotate.service masked; unmask it so the timer can launch rotations.")
            elif service_load == "not-found":
                lines.append("⚠ logrotate.service missing; reinstall the logrotate package.")
    else:
        lines.append("systemctl unavailable; relying on cron scheduling for logrotate.")

    cron_path = LOGROTATE_CRON_PATH
    if cron_path.exists():
        try:
            stat_result = cron_path.lstat()
        except OSError as exc:
            lines.append(f"⚠ Cron job {cron_path}: unable to stat ({exc}).")
        else:
            issues: List[str] = []
            permissions = stat.S_IMODE(stat_result.st_mode)
            if stat.S_ISLNK(stat_result.st_mode):
                issues.append("is a symbolic link")
            if permissions & stat.S_IWOTH:
                issues.append("world-writable")
            if permissions & stat.S_IWGRP:
                issues.append("group-writable")
            if not permissions & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                issues.append("not executable")
            owner = _describe_owner(stat_result.st_uid, stat_result.st_gid)
            mode_text = _format_mode(stat_result.st_mode)
            if issues:
                lines.append(
                    f"⚠ Cron job {cron_path}: {'; '.join(issues)} ({owner} {mode_text})."
                )
            else:
                cron_ok = True
                lines.append(
                    f"Cron job {cron_path}: executable ({owner} {mode_text}); cron.daily can trigger rotations."
                )
    else:
        if timer_ok:
            lines.append(f"Cron job {cron_path}: not installed — relying on logrotate.timer.")
        elif systemctl_available:
            lines.append(
                f"⚠ Cron job {cron_path}: missing; enable logrotate.timer or install the cron script."
            )

    if not timer_ok and not cron_ok:
        lines.append(
            "⚠ No logrotate scheduler detected; enable logrotate.timer or deploy /etc/cron.daily/logrotate."
        )

    lines.extend(schedule_lines)

    return lines


def analyze_logrotate_config() -> List[str]:
    """Inspect logrotate configuration for IDS log coverage and hygiene."""

    lines: List[str] = []
    config_path = resolve_logrotate_path()
    candidate_text = ", ".join(str(path) for path in LOGROTATE_CANDIDATES[:-1])
    scheduler_lines = analyze_logrotate_scheduler()

    if config_path is None:
        lines.append(
            f"⚠ Logrotate configuration not found; deploy policy under {candidate_text}."
        )
        if not shutil.which("logrotate"):
            lines.append(
                "⚠ logrotate binary missing; install it to prevent unchecked log growth."
            )
        lines.extend(scheduler_lines)
        return lines

    if config_path == LOGROTATE_SAMPLE:
        lines.append(
            f"⚠ Sample logrotate policy detected at {config_path}; copy to {candidate_text}"
            " so rotations execute automatically."
        )
        if not shutil.which("logrotate"):
            lines.append(
                "⚠ logrotate binary missing; install it to prevent unchecked log growth."
            )
        lines.extend(scheduler_lines)
        return lines

    if not shutil.which("logrotate"):
        lines.append(
            "⚠ logrotate binary missing; install the package to enforce log retention."
        )

    lines.append(f"Policy: {config_path}")

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"⚠ Unable to read logrotate configuration {config_path}: {exc}"]

    blocks = _parse_logrotate_blocks(text)
    if not blocks:
        return [
            f"⚠ {config_path} defines no log rotation blocks; add IDS log files to avoid growth.",
        ]

    snapshots: Dict[Path, Tuple[bool, Optional[int]]] = {}
    for log_path in LOGROTATE_TARGETS:
        matched_pattern: Optional[str] = None
        block_lines: List[str] = []
        for pattern, candidate_lines in blocks:
            if fnmatch.fnmatch(str(log_path), pattern):
                matched_pattern = pattern
                block_lines = candidate_lines
                break

        if matched_pattern is None:
            lines.append(
                f"⚠ {log_path.name}: not covered by {config_path}; rotate manually or extend the policy."
            )
            continue

        directives: Dict[str, str] = {}
        for entry in block_lines:
            if not entry or entry.startswith("#"):
                continue
            key = entry.split()[0].lower()
            directives.setdefault(key, entry)

        issues: List[str] = []
        missing = sorted(
            directive for directive in LOGROTATE_REQUIRED_DIRECTIVES if directive not in directives
        )
        if missing:
            issues.append(f"missing {', '.join(missing)}")

        retention_value: Optional[int] = None
        rotate_line = directives.get("rotate")
        if rotate_line:
            parts = rotate_line.split()
            if len(parts) < 2:
                issues.append("rotate missing count")
            else:
                try:
                    retention_value = int(parts[1])
                    if retention_value < 3:
                        issues.append(f"rotate {retention_value} too low")
                except ValueError:
                    issues.append(f"rotate '{parts[1]}' not numeric")
        else:
            issues.append("rotate directive absent")

        create_line = directives.get("create")
        mode_token: Optional[str] = None
        owner: Optional[str] = None
        group: Optional[str] = None
        if create_line:
            parts = create_line.split()
            if len(parts) < 4:
                issues.append("create incomplete")
            else:
                mode_token = parts[1]
                owner = parts[2]
                group = parts[3]
                try:
                    mode_value = int(mode_token, 8)
                    if mode_value & stat.S_IWOTH:
                        issues.append(f"mode {mode_token} world-writable")
                    if mode_value & stat.S_IWGRP:
                        issues.append(f"mode {mode_token} group-writable")
                    if mode_value & (stat.S_IROTH | stat.S_IXOTH):
                        issues.append(f"mode {mode_token} world-accessible")
                except ValueError:
                    issues.append(f"mode '{mode_token}' invalid")
                if owner != "root":
                    issues.append(f"owner {owner}")
                if group not in SECURE_LOG_GROUPS:
                    issues.append(f"group {group}")
        else:
            issues.append("create directive absent")

        su_line = directives.get("su")
        su_user: Optional[str] = None
        su_group: Optional[str] = None
        if su_line:
            parts = su_line.split()
            if len(parts) < 3:
                issues.append("su incomplete")
            else:
                su_user = parts[1]
                su_group = parts[2]
                if su_user != LOGROTATE_SECURE_USER:
                    issues.append(f"su user {su_user}")
                if su_group not in SECURE_LOG_GROUPS:
                    issues.append(f"su group {su_group}")
        else:
            issues.append("su directive absent")

        olddir_line = directives.get("olddir")
        olddir_status: Optional[str] = None
        if olddir_line:
            olddir_issues, olddir_status = _analyze_logrotate_olddir(log_path, olddir_line)
            if olddir_issues:
                issues.extend(olddir_issues)

        pattern_note = "" if matched_pattern == str(log_path) else f" via {matched_pattern}"
        if issues:
            lines.append(f"⚠ {log_path.name}: {'; '.join(issues)}{pattern_note}.")
            continue

        status_parts: List[str] = []
        if retention_value is not None:
            status_parts.append(f"rotate {retention_value}x")
        status_parts.append("daily")
        if mode_token and owner and group:
            status_parts.append(f"create {mode_token} {owner}:{group}")
        if su_user and su_group:
            status_parts.append(f"su {su_user}:{su_group}")
        if olddir_status:
            status_parts.append(olddir_status)

        metadata_warnings: List[str] = []
        try:
            stat_result = log_path.lstat()
        except FileNotFoundError:
            status_parts.append("log not created yet")
            stat_result = None
        except OSError as exc:
            lines.append(
                f"⚠ {log_path.name}: unable to stat log file {log_path}: {exc}."
            )
            stat_result = None

        if stat_result is not None:
            mode_value = stat_result.st_mode
            owner_name = None
            group_name = None
            try:
                owner_name = pwd.getpwuid(stat_result.st_uid).pw_name
            except KeyError:
                owner_name = str(stat_result.st_uid)
            try:
                group_name = grp.getgrgid(stat_result.st_gid).gr_name
            except KeyError:
                group_name = str(stat_result.st_gid)

            status_parts.append(
                f"mode {_format_mode(mode_value)} {owner_name}:{group_name}"
            )

            if stat.S_ISLNK(mode_value):
                metadata_warnings.append("is a symbolic link")
            elif not stat.S_ISREG(mode_value):
                metadata_warnings.append("not a regular file")
            else:
                size_kib = stat_result.st_size / 1024
                status_parts.append(f"current size {size_kib:.1f} KiB")

            permissions = stat.S_IMODE(mode_value)
            if permissions & stat.S_IWOTH:
                metadata_warnings.append("world-writable")
            if permissions & stat.S_IWGRP:
                metadata_warnings.append("group-writable")
            if permissions & (stat.S_IROTH | stat.S_IXOTH):
                metadata_warnings.append("world-accessible")
            if owner_name != "root":
                metadata_warnings.append(f"owner {owner_name}")
            if group_name not in SECURE_LOG_GROUPS:
                metadata_warnings.append(f"group {group_name}")

            parent = log_path.parent
            try:
                parent_stat = parent.lstat()
            except OSError as exc:
                metadata_warnings.append(f"unable to stat parent {parent}: {exc}")
            else:
                try:
                    parent_owner = pwd.getpwuid(parent_stat.st_uid).pw_name
                except KeyError:
                    parent_owner = str(parent_stat.st_uid)
                try:
                    parent_group = grp.getgrgid(parent_stat.st_gid).gr_name
                except KeyError:
                    parent_group = str(parent_stat.st_gid)

                if stat.S_ISLNK(parent_stat.st_mode):
                    metadata_warnings.append(f"parent {parent} is a symlink")
                parent_mode = stat.S_IMODE(parent_stat.st_mode)
                if parent_mode & stat.S_IWOTH:
                    metadata_warnings.append(f"parent {parent} world-writable")
                if parent_mode & stat.S_IWGRP and parent_group not in SECURE_LOG_GROUPS:
                    metadata_warnings.append(
                        f"parent {parent} group-writable (group {parent_group})"
                    )
                if parent_owner != "root":
                    metadata_warnings.append(
                        f"parent {parent} owner {parent_owner}"
                    )

            ancestor_issues, ancestor_error = _enumerate_insecure_log_ancestors(log_path)
            if ancestor_error:
                metadata_warnings.append(ancestor_error)
            elif ancestor_issues:
                metadata_warnings.extend(ancestor_issues)

        if metadata_warnings:
            lines.append(
                f"⚠ {log_path.name}: {'; '.join(metadata_warnings)}; harden log file permissions."
            )

        if pattern_note:
            status_parts.append(f"pattern {matched_pattern}")
        lines.append(f"{log_path.name}: {', '.join(status_parts)}.")

        if stat_result is None:
            snapshots[log_path] = (False, None)
        else:
            snapshots[log_path] = (True, stat_result.st_size)

    if len(lines) == 1:
        lines.append("All monitored logs are protected by logrotate.")

    lines.extend(_summarize_logrotate_state(config_path, text, snapshots))
    lines.extend(scheduler_lines)

    return lines


def analyze_unit_availability(units: Sequence[Tuple[str, str]]) -> List[str]:
    if not shutil.which("systemctl"):
        return ["systemctl unavailable; cannot inspect unit load states."]

    seen: Set[str] = set()
    issue_lines: List[str] = []
    healthy_units: List[str] = []

    for unit, label in units:
        if unit in seen:
            continue
        seen.add(unit)
        info = _query_unit_state(unit)
        status = _format_unit_status(info)
        load_state = info.load_state.lower() if info else "unknown"
        unit_file_state = info.unit_file_state.lower() if info else ""

        if load_state in {"not-found", "masked", "error"}:
            detail = f" ({info.detail})" if info and info.detail and load_state == "error" else ""
            if load_state == "not-found":
                issue_lines.append(
                    f"⚠ {label} ({unit}) missing; reinstall or deploy the unit file."
                )
            elif load_state == "masked":
                issue_lines.append(
                    f"⚠ {label} ({unit}) masked; run systemctl unmask {unit}."
                )
            else:
                issue_lines.append(
                    f"⚠ {label} ({unit}) load state error{detail}; investigate systemd status."
                )
        elif unit_file_state == "masked":
            issue_lines.append(
                f"⚠ {label} ({unit}) unit file masked; run systemctl unmask {unit}."
            )
        else:
            descriptor = status if status not in {"inactive", "unknown"} else "loaded"
            healthy_units.append(f"{label}: {descriptor}")

    if not issue_lines:
        if healthy_units:
            sample = ", ".join(healthy_units[:4])
            return [f"All monitored units are loaded ({sample})."]
        return ["All monitored units are loaded and accessible."]

    if healthy_units:
        issue_lines.append(
            f"Healthy units: {', '.join(healthy_units[:4])}{'...' if len(healthy_units) > 4 else ''}."
        )
    return issue_lines


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

    systemctl_available = shutil.which("systemctl") is not None

    for key, (label, dependencies) in CONFIG_FEATURE_DEPENDENCIES.items():
        value = config.get(key)
        if value not in {"0", "1"} or not dependencies:
            continue
        enabled_flag = value == "1"
        if not systemctl_available:
            if enabled_flag:
                lines.append(
                    f"⚠ {label} ({key}) enabled but unable to verify supporting units without systemctl."
                )
                issues = True
            continue

        mismatch = False
        status_details: List[Tuple[str, str, str, str]] = []
        for dependency in dependencies:
            unit = dependency.unit
            description = dependency.description
            info = _query_unit_state(unit)
            status = _format_unit_status(info)
            load_state = info.load_state.lower() if info else ""
            unit_file_state = info.unit_file_state.lower() if info else ""
            enable_state = _enablement_from_systemctl(unit)
            normalized_enable_state = enable_state.lower()
            status_details.append(
                (
                    description,
                    status or "inactive",
                    enable_state or "unknown",
                    load_state or "loaded",
                )
            )

            if info is not None and load_state not in {"loaded", ""}:
                mismatch = True
                issues = True
                if load_state == "not-found":
                    lines.append(
                        f"⚠ {label} dependency {description} ({unit}) missing; reinstall the unit."
                    )
                elif load_state == "masked":
                    lines.append(
                        f"⚠ {label} dependency {description} ({unit}) is masked; run systemctl unmask {unit}."
                    )
                else:
                    detail = f" ({info.detail})" if info.detail else ""
                    lines.append(
                        f"⚠ {label} dependency {description} ({unit}) load state {load_state or 'unknown'}{detail}."
                    )
                if unit_file_state == "masked":
                    lines.append(
                        f"⚠ {label} dependency {description} ({unit}) unit file masked; run systemctl unmask {unit}."
                    )
                continue

            if unit_file_state == "masked":
                mismatch = True
                issues = True
                lines.append(
                    f"⚠ {label} dependency {description} ({unit}) unit file is masked; unmask it."
                )
                continue

            normalized_status = (
                info.active_state.lower() if info and info.active_state else ""
            )

            if dependency.kind == DEPENDENCY_KIND_TIMER:
                if enabled_flag:
                    if normalized_status not in {"active", "activating"}:
                        mismatch = True
                        issues = True
                        lines.append(
                            f"⚠ {label} enabled but {description} ({unit}) is {status or 'inactive'}."
                        )
                    if (
                        normalized_enable_state not in ENABLEMENT_OK_STATES
                        and normalized_enable_state not in ENABLEMENT_ACCEPTABLE_STATES
                    ):
                        mismatch = True
                        issues = True
                        lines.append(
                            f"⚠ {label} enabled but {description} ({unit}) enablement is {enable_state or 'unknown'}."
                        )
                else:
                    if normalized_status in {"active", "activating"}:
                        mismatch = True
                        issues = True
                        lines.append(
                            f"⚠ {label} disabled but {description} ({unit}) still {status or 'active'}; disable the timer or update {key}."
                        )
                    if normalized_enable_state in ENABLEMENT_OK_STATES:
                        mismatch = True
                        issues = True
                        lines.append(
                            f"⚠ {label} disabled but {description} ({unit}) remains enabled ({enable_state or 'enabled'})."
                        )
            else:
                if enabled_flag and normalized_status == "failed":
                    mismatch = True
                    issues = True
                    lines.append(
                        f"⚠ {label} enabled but {description} ({unit}) is failed; inspect logs."
                    )
                if not enabled_flag and normalized_status in {"active", "activating", "running"}:
                    mismatch = True
                    issues = True
                    lines.append(
                        f"⚠ {label} disabled but {description} ({unit}) running; stop the service or update {key}."
                    )
                if normalized_enable_state.startswith("error"):
                    mismatch = True
                    issues = True
                    lines.append(
                        f"⚠ Unable to determine enablement for {description} ({unit}): {enable_state}."
                    )

        if not mismatch:
            state_word = "enabled" if enabled_flag else "disabled"
            summary_parts = []
            for desc, status_text, enable_state, load_state in status_details:
                annotations: List[str] = []
                if load_state and load_state not in {"loaded", ""}:
                    annotations.append(f"load={load_state}")
                if enable_state and enable_state not in {"", "unknown"}:
                    annotations.append(f"enablement={enable_state}")
                annotation_text = f" ({', '.join(annotations)})" if annotations else ""
                summary_parts.append(f"{desc} {status_text}{annotation_text}")
            summary = ", ".join(summary_parts)
            lines.append(f"{label}: {state_word}; {summary}.")

    if not issues:
        lines.append("Configuration settings validated successfully.")

    return lines


def build_views() -> List[Tuple[str, List[Tuple[str, Sequence]]]]:
    stats = load_json(ALERT_STATS)
    config_path, config, config_duplicates, config_malformed = detect_config_with_diagnostics()
    services = gather_service_lines()
    enablement = gather_enablement_lines()
    unit_availability = analyze_unit_availability(SERVICES)
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
            ("Autoblock state", AUTOBLOCK_STATE),
            ("Threat feed state", THREAT_FEED_STATE),
            ("Alert report state", ALERT_REPORT_STATE),
            ("Alert report log", ALERT_REPORT_LOG),
            ("Alert source log", ALERT_REPORT_SOURCE_LOG),
            ("Process monitor baseline", PROCESS_MONITOR_BASELINE),
            ("Port monitor baseline", PORT_MONITOR_BASELINE),
            ("Port monitor alert log", PORT_MONITOR_ALERT_LOG),
            ("SSH whitelist", SSH_WHITELIST_PATH),
            ("SSH blacklist", SSH_BLACKLIST_PATH),
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
    filesystem_entries.append(("Threat feed state", THREAT_FEED_STATE))
    filesystem_entries.append(("Threat feed log", DEFAULT_LOGS["threat_feed"]))
    filesystem_entries.append(("Autoblock state", AUTOBLOCK_STATE))
    filesystem_entries.append(("Autoblock log", DEFAULT_LOGS["autoblock"]))
    filesystem_entries.append(("Process monitor baseline", PROCESS_MONITOR_BASELINE))
    filesystem_entries.append(("Alert source log", ALERT_REPORT_SOURCE_LOG))
    filesystem_entries.append(("Alert report state", ALERT_REPORT_STATE))
    filesystem_entries.append(("Alert report log", ALERT_REPORT_LOG))
    filesystem_entries.append(("Network I/O rsyslog rules", NETWORK_IO_RSYSLOG_CONF))
    filesystem_entries.append(("Network I/O logrotate policy", NETWORK_IO_LOGROTATE_CONF))
    for label, log_path, _ in NETWORK_IO_LOGS:
        filesystem_entries.append((f"{label} log", log_path))
    filesystem_entries.append(("Internet access log", INTERNET_ACCESS_LOG))
    filesystem_entries.append(("Anti-wipe monitor log", ANTI_WIPE_LOG))
    filesystem_entries.append(("Anti-wipe monitor script", ANTI_WIPE_SCRIPT))
    filesystem_entries.append(("SSH whitelist", SSH_WHITELIST_PATH))
    filesystem_entries.append(("SSH blacklist", SSH_BLACKLIST_PATH))
    filesystem_entries.append(("SSH access control script", SSH_ACCESS_SCRIPT))
    filesystem_entries.append(("Resource monitor log", RESOURCE_MONITOR_LOG))
    filesystem_entries.append(("Port monitor baseline", PORT_MONITOR_BASELINE))
    filesystem_entries.append(("Port monitor alert log", PORT_MONITOR_ALERT_LOG))
    filesystem_entries.append(("systemd-timesyncd configuration", TIMESYNCD_CONFIG))
    filesystem_hygiene = analyze_filesystem_hygiene(filesystem_entries)
    logrotate_status = analyze_logrotate_config()
    snapshot_integrity = analyze_snapshot_integrity()
    cpu_capacity = analyze_cpu_capacity()
    time_sync_status = analyze_time_synchronization()
    memory_capacity = analyze_memory_capacity()
    disk_capacity = analyze_disk_capacity()
    inode_capacity = analyze_inode_capacity()
    config_integrity = analyze_config_integrity(
        config_path, config, config_duplicates, config_malformed
    )
    threat_feed_status = analyze_threat_feed_blocklist()
    autoblock_status = analyze_autoblock_state()
    process_monitor_status = analyze_process_monitor_baseline()
    network_io_status = analyze_network_io_monitor()
    internet_access_status = analyze_internet_access_monitor()
    alert_report_status = analyze_alert_reporting()
    ssh_access_status = analyze_ssh_access_controls()
    anti_wipe_status = analyze_anti_wipe_monitor()
    resource_monitor_status = analyze_resource_monitor_log()
    port_monitor_status = analyze_port_monitor_baseline()

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
        ("Autoblock State", autoblock_status),
        ("Process Monitor Baseline", process_monitor_status),
        ("Network I/O Monitor", network_io_status),
        ("Internet Access Monitor", internet_access_status),
        ("Alert Reporting", alert_report_status),
        ("SSH Access Controls", ssh_access_status),
        ("Anti-Wipe Monitor", anti_wipe_status),
        ("Resource Monitor", resource_monitor_status),
        ("Port Monitor Baseline", port_monitor_status),
        ("Threat Feed Blocklist", threat_feed_status),
        ("Time Synchronization", time_sync_status),
        ("CPU Capacity", cpu_capacity),
        ("Health Check Summary", health_summary),
        ("Recent Health Log Entries", health_tail),
        (
            "Maintenance Tips",
            [
                "Press V to run a health check without restarting services.",
                "Press J to inspect the full health check log.",
                "Press 0 to open raw alert telemetry for deep inspection.",
                "Press : to review the alert report log for hourly summaries.",
                "Press < to review the alert report state pointer before troubleshooting notifications.",
                "Press 1 to review the autoblock state before adjusting thresholds.",
                "Press 2 to review the threat feed blocklist state before forcing updates.",
                "Press - to review the process monitor baseline before resetting detections.",
                "Press , to review inbound network logs for unexpected sources.",
                "Press . to review outbound network logs for suspicious destinations.",
                "Press / to review the internet access monitor log for connectivity attempts.",
                "Press ' to review the SSH whitelist before applying new allow-list entries.",
                'Press " to review the SSH blacklist for recently blocked sources.',
                "Press ] to review the anti-wipe monitor log for tampering alerts.",
                "Press ; to review the resource monitor log before tuning limits.",
                "Press = to review the port monitor baseline before trusting new allowances.",
                "Press [ to review the port monitor alert log for unexpected listeners.",
                "Press 3 to review live CPU load averages.",
                "Review Configuration Integrity under Resilience after editing nn_ids.conf.",
                "Review Unit Enablement under Resilience to confirm services auto-start.",
                "Review Log Rotation under Resilience to confirm log retention policies.",
                "Review Process Monitor Baseline under Resilience to confirm inventory freshness.",
                "Review Threat Feed Blocklist under Resilience to confirm remote feeds are current.",
                "Review Internet Access Monitor under Resilience to confirm connectivity automation.",
                "Review Alert Reporting under Resilience to confirm notifications remain healthy.",
                "Review SSH Access Controls under Resilience to confirm firewall enforcement.",
                        "Review Anti-Wipe Monitor under Resilience to confirm tamper detection coverage.",
                "Review Time Synchronization under Resilience to confirm clocks remain aligned.",
                "Review CPU Capacity under Resilience to monitor compute headroom.",
                "Review Snapshot Integrity under Resilience to confirm backup coverage.",
                "Review Memory Capacity under Resilience to watch for memory pressure.",
                "Review Disk Capacity under Resilience to prevent low-storage outages.",
                "Review Inode Capacity under Resilience to catch inode exhaustion early.",
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
                ("Unit Availability", unit_availability),
                ("Unit Enablement", enablement),
                ("File Freshness", freshness),
                ("Configuration Integrity", config_integrity),
                ("Filesystem Hygiene", filesystem_hygiene),
                ("Snapshot Integrity", snapshot_integrity),
                ("Autoblock State", autoblock_status),
                ("Process Monitor Baseline", process_monitor_status),
                ("Network I/O Monitor", network_io_status),
                ("Internet Access Monitor", internet_access_status),
                ("Alert Reporting", alert_report_status),
                ("SSH Access Controls", ssh_access_status),
                ("Anti-Wipe Monitor", anti_wipe_status),
                ("Resource Monitor", resource_monitor_status),
                ("Port Monitor Baseline", port_monitor_status),
                ("Threat Feed Blocklist", threat_feed_status),
                ("Time Synchronization", time_sync_status),
                ("CPU Capacity", cpu_capacity),
                ("Memory Capacity", memory_capacity),
                ("Disk Capacity", disk_capacity),
                ("Inode Capacity", inode_capacity),
                ("Log Rotation", logrotate_status),
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


def open_threat_feed_state(stdscr: "curses._CursesWindow") -> str:
    if not THREAT_FEED_STATE.exists():
        return f"Threat feed state not found: {THREAT_FEED_STATE}"
    return open_log(stdscr, THREAT_FEED_STATE)


def open_autoblock_state(stdscr: "curses._CursesWindow") -> str:
    if not AUTOBLOCK_STATE.exists():
        return f"Autoblock state not found: {AUTOBLOCK_STATE}"
    return open_log(stdscr, AUTOBLOCK_STATE)


def open_process_baseline(stdscr: "curses._CursesWindow") -> str:
    if not PROCESS_MONITOR_BASELINE.exists():
        return f"Process monitor baseline not found: {PROCESS_MONITOR_BASELINE}"
    return open_log(stdscr, PROCESS_MONITOR_BASELINE)


def open_port_baseline(stdscr: "curses._CursesWindow") -> str:
    if not PORT_MONITOR_BASELINE.exists():
        return f"Port monitor baseline not found: {PORT_MONITOR_BASELINE}"
    return open_log(stdscr, PORT_MONITOR_BASELINE)


def open_logrotate_config(stdscr: "curses._CursesWindow") -> str:
    path = resolve_logrotate_path()
    if path is None:
        expected = ", ".join(str(candidate) for candidate in LOGROTATE_CANDIDATES[:-1])
        return f"Logrotate configuration not found; expected under {expected}"
    message = open_log(stdscr, path)
    if path == LOGROTATE_SAMPLE:
        return f"{message} — deploy this sample to /etc/logrotate.d to activate rotations"
    return message


def open_logrotate_state(stdscr: "curses._CursesWindow") -> str:
    config_path = resolve_logrotate_path()
    config_text: Optional[str] = None
    if config_path and config_path.exists():
        try:
            config_text = config_path.read_text(encoding="utf-8")
        except OSError:
            config_text = None

    state_path, candidates = resolve_logrotate_state_path(config_text)
    if state_path is None:
        expected = ", ".join(str(path) for path in candidates) if candidates else "(no default state path)"
        return f"Logrotate state file not found; expected under {expected}"
    return open_log(stdscr, state_path)


def open_time_sync_status(stdscr: "curses._CursesWindow") -> str:
    if TIMEDATECTL_PATH:
        open_external(stdscr, [TIMEDATECTL_PATH, "status"])
        return "Displayed timedatectl status"
    if CHRONYC_PATH:
        open_external(stdscr, [CHRONYC_PATH, "tracking"])
        return "Displayed chronyc tracking"
    return "No time synchronization utilities available"


def open_memory_usage(stdscr: "curses._CursesWindow") -> str:
    command = shutil.which("free") or "free"
    open_external(stdscr, [command, "-h"])
    return "Displayed memory usage"


def open_cpu_load(stdscr: "curses._CursesWindow") -> str:
    command = shutil.which("uptime")
    if command:
        open_external(stdscr, [command])
        return "Displayed CPU load averages"

    if LOADAVG_PATH.exists():
        cat = shutil.which("cat") or "cat"
        open_external(stdscr, [cat, str(LOADAVG_PATH)])
        return f"Displayed {LOADAVG_PATH}"

    return f"Unable to inspect CPU load; {LOADAVG_PATH} not available"


def open_disk_usage(stdscr: "curses._CursesWindow") -> str:
    command = shutil.which("df") or "df"
    open_external(stdscr, [command, "-h"])
    return "Displayed disk usage"


def open_inode_usage(stdscr: "curses._CursesWindow") -> str:
    command = shutil.which("df") or "df"
    open_external(stdscr, [command, "-ih"])
    return "Displayed inode usage"


def open_latest_snapshot(stdscr: "curses._CursesWindow") -> str:
    root, candidates = resolve_snapshot_root()
    if root is None:
        expected = ", ".join(str(path) for path in candidates)
        return f"Snapshot root not found; expected under {expected}"

    try:
        directories = [entry for entry in root.iterdir() if entry.is_dir()]
    except OSError as exc:
        return f"Unable to enumerate {root}: {exc}"

    snapshots: List[Tuple[datetime, Path]] = []
    for entry in directories:
        timestamp = _parse_snapshot_timestamp(entry.name)
        if timestamp is None:
            continue
        snapshots.append((timestamp, entry))

    if not snapshots:
        return f"No snapshots present under {root}"

    snapshots.sort(key=lambda item: item[0])
    latest_path = snapshots[-1][1]
    viewer = shutil.which("ls") or "ls"
    open_external(stdscr, [viewer, "-l", str(latest_path)])
    return f"Listed snapshot {latest_path}"


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
            (",", ("View inbound network log", lambda: open_log(stdscr, DEFAULT_LOGS["network_in"]))),
            (".", ("View outbound network log", lambda: open_log(stdscr, DEFAULT_LOGS["network_out"]))),
            ("/", ("View internet access log", lambda: open_log(stdscr, DEFAULT_LOGS["internet_access"]))),
            ("'", ("View SSH whitelist", lambda: open_log(stdscr, DEFAULT_LOGS["ssh_whitelist"]))),
            ("\"", ("View SSH blacklist", lambda: open_log(stdscr, DEFAULT_LOGS["ssh_blacklist"]))),
            (";", ("View resource monitor log", lambda: open_log(stdscr, DEFAULT_LOGS["resource"]))),
            ("[", ("View port monitor log", lambda: open_log(stdscr, DEFAULT_LOGS["port_monitor"]))),
            ("]",
                (
                    "View anti-wipe monitor log",
                    lambda: open_log(stdscr, DEFAULT_LOGS["anti_wipe"]),
                ),
            ),
            ("g", ("View GA Tech process log", lambda: open_log(stdscr, DEFAULT_LOGS["ga_process"]))),
            ("s", ("View GA Tech syscall log", lambda: open_log(stdscr, DEFAULT_LOGS["ga_syscall"]))),
            ("t", ("View threat feed log", lambda: open_log(stdscr, DEFAULT_LOGS["threat_feed"]))),
            ("j", ("View health check log", lambda: open_log(stdscr, HEALTH_LOG))),
            ("0", ("View raw alert telemetry", lambda: open_log(stdscr, ALERT_STATS))),
            (":", ("View alert report log", lambda: open_log(stdscr, DEFAULT_LOGS["alert_report"]))),
            ("<", ("View alert report state", lambda: open_log(stdscr, ALERT_REPORT_STATE))),
            ("1", ("View autoblock state", lambda: open_autoblock_state(stdscr))),
            ("2", ("View threat feed state", lambda: open_threat_feed_state(stdscr))),
            ("-", ("View process baseline", lambda: open_process_baseline(stdscr))),
            ("=", ("View port baseline", lambda: open_port_baseline(stdscr))),
            ("3", ("View CPU load", lambda: open_cpu_load(stdscr))),
            ("4", ("View memory usage", lambda: open_memory_usage(stdscr))),
            ("5", ("View logrotate policy", lambda: open_logrotate_config(stdscr))),
            ("6", ("View logrotate state", lambda: open_logrotate_state(stdscr))),
            ("7", ("List latest snapshot directory", lambda: open_latest_snapshot(stdscr))),
            ("8", ("View disk usage", lambda: open_disk_usage(stdscr))),
            ("9", ("View inode usage", lambda: open_inode_usage(stdscr))),
            (")", ("View time synchronization status", lambda: open_time_sync_status(stdscr))),
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
