#!/usr/bin/env python3
"""Run a focused set of health checks for the neural network IDS stack."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
import pwd
import grp
import shutil
import stat
import subprocess
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple, Set

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
THREAT_FEED_STATE = Path("/var/lib/nn_ids/threat_feed_state.json")
THREAT_FEED_LOG = Path("/var/log/threat_feed_blocklist.log")
THREAT_FEED_STALE_THRESHOLD = timedelta(days=2)
THREAT_FEED_CLOCK_SKEW = timedelta(minutes=5)
THREAT_FEED_DEFAULT_ENDPOINTS: Sequence[str] = (
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
)
THREAT_FEED_ENDPOINT_KEY = "NN_IDS_THREAT_FEED_ENDPOINTS"
THREAT_FEED_PROBE_TIMEOUT = 5.0
THREAT_FEED_USER_AGENT = "nn-ids-healthcheck/1.0"
AUTOBLOCK_STATE = Path("/var/lib/nn_ids/autoblock_state.json")
AUTOBLOCK_LOG = Path("/var/log/nn_ids_autoblock.log")
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
RESOURCE_MONITOR_SERVICE = "nn_ids_resource_monitor.service"
RESOURCE_MONITOR_TIMER = "nn_ids_resource_monitor.timer"
RESOURCE_MONITOR_STALE_THRESHOLD = timedelta(minutes=15)
RESOURCE_MONITOR_CLOCK_SKEW = timedelta(minutes=5)
RESOURCE_MONITOR_TIMER_INTERVAL = timedelta(minutes=5)
RESOURCE_MONITOR_TIMER_GRACE = timedelta(minutes=2)
RESOURCE_MONITOR_SPIKE_WINDOW = timedelta(hours=1)
RESOURCE_MONITOR_SPIKE_ALERT_COUNT = 3
NETWORK_IO_RSYSLOG_CONF = Path("/etc/rsyslog.d/20-iptables.conf")
NETWORK_IO_LOGROTATE_CONF = Path("/etc/logrotate.d/network_io")
NETWORK_IO_SERVICE = "network_io_monitor.service"
NETWORK_IO_CLOCK_SKEW = timedelta(minutes=5)
NETWORK_IO_STALE_THRESHOLD = timedelta(days=7)
NETWORK_IO_EXPECTED_RULES: Sequence[Tuple[str, Path]] = (
    ("INBOUND: ", Path("/var/log/inbound.log")),
    ("OUTBOUND: ", Path("/var/log/outbound.log")),
    ("INBOUND6: ", Path("/var/log/inbound6.log")),
    ("OUTBOUND6: ", Path("/var/log/outbound6.log")),
)
INTERNET_ACCESS_LOG = Path("/var/log/internet_access.log")
INTERNET_ACCESS_SERVICE = "internet_access_monitor.service"
INTERNET_ACCESS_TIMER = "internet_access_monitor.timer"
INTERNET_ACCESS_STALE_THRESHOLD = timedelta(minutes=15)
INTERNET_ACCESS_CLOCK_SKEW = timedelta(minutes=5)
INTERNET_ACCESS_TIMER_INTERVAL = timedelta(minutes=5)
INTERNET_ACCESS_TIMER_GRACE = timedelta(minutes=2)
INTERNET_ACCESS_SUCCESS_MARKERS = (
    "internet access verified",
    "internet access restored",
)
ANTI_WIPE_LOG = Path("/var/log/anti_wipe.log")
ANTI_WIPE_SCRIPT = Path("/usr/local/bin/anti_wipe_monitor.sh")
ANTI_WIPE_SERVICE = "anti_wipe_monitor.service"
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
SSH_WHITELIST_FALLBACKS: Sequence[Path] = (
    Path("/usr/local/etc/ssh_whitelist.conf"),
    Path(__file__).resolve().parent / "ssh_whitelist.conf",
)
SSH_BLACKLIST_FALLBACKS: Sequence[Path] = (
    Path("/usr/local/etc/ssh_blacklist.conf"),
    Path(__file__).resolve().parent / "ssh_blacklist.conf",
)
SSH_CHAIN_NAME = "SSH_ACCESS"
IPTABLES_BINARY = shutil.which("iptables")

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

CONFIG_BOOL_FIELDS: Dict[str, str] = {
    "NN_IDS_SANITIZE": "Packet sanitization",
    "NN_IDS_NOTIFY": "Notification toggle",
    "NN_IDS_AUTOBLOCK": "Automatic IP blocking",
    "NN_IDS_THREAT_FEED": "Threat feed updates",
}

CONFIG_FLOAT_FIELDS: Dict[str, Tuple[str, float, float]] = {
    "NN_IDS_THRESHOLD": ("Alert probability threshold", 0.0, 1.0),
    "NN_SYS_THRESHOLD": ("Syscall probability threshold", 0.0, 1.0),
    "GA_PROC_THRESHOLD": ("GA Tech process threshold", 0.0, 1.0),
    "GA_PROC_MIN_RISK": ("GA Tech process minimum risk", 0.0, 1.0),
}

CONFIG_INT_FIELDS: Dict[str, Tuple[str, int, int]] = {
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


@dataclass(frozen=True)
class ConfigurationSnapshot:
    path: Path
    data: Dict[str, str]
    duplicates: List[str] = field(default_factory=list)
    malformed: List[str] = field(default_factory=list)


_CONFIG_SNAPSHOT: Optional[ConfigurationSnapshot] = None
_CONFIG_SNAPSHOT_ERRORS: bool = False
_CONFIG_SNAPSHOT_LOADED: bool = False


CONFIG_FEATURE_DEPENDENCIES: Dict[str, Tuple[str, Sequence[UnitDependency]]] = {
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
            UnitDependency(ALERT_REPORT_TIMER, "Notification report timer"),
            UnitDependency(
                ALERT_REPORT_SERVICE,
                "Notification report service",
                DEPENDENCY_KIND_SERVICE,
            ),
        ),
    ),
}

UNIT_AUTO_START_STATES = {"enabled", "linked", "alias"}
UNIT_ALLOWED_ENABLE_STATES = UNIT_AUTO_START_STATES | {"static", "indirect", "generated"}

PROTECTED_PATHS: Sequence[Tuple[Path, str]] = (
    (ALERT_STATS.parent, "Alert telemetry directory"),
    (ALERT_STATS, "Alert telemetry"),
    (MODEL.parent, "Model artifact directory"),
    (MODEL, "Model artifact"),
    (LOG.parent, "Health log directory"),
    (LOG, "Health log"),
    (THREAT_FEED_STATE, "Threat feed state"),
    (THREAT_FEED_LOG, "Threat feed log"),
    (AUTOBLOCK_STATE, "Autoblock state"),
    (AUTOBLOCK_LOG, "Autoblock log"),
    (PROCESS_MONITOR_BASELINE, "Process monitor baseline"),
    (PORT_MONITOR_BASELINE, "Port monitor baseline"),
    (RESOURCE_MONITOR_LOG, "Resource monitor log"),
    (INTERNET_ACCESS_LOG, "Internet access log"),
    (ALERT_REPORT_LOG, "Alert report log"),
    (ALERT_REPORT_STATE, "Alert report state"),
    (ALERT_REPORT_SOURCE_LOG, "Alert source log"),
    (ANTI_WIPE_LOG, "Anti-wipe monitor log"),
    (ANTI_WIPE_SCRIPT, "Anti-wipe monitor script"),
    (SSH_WHITELIST_PATH, "SSH whitelist"),
    (SSH_BLACKLIST_PATH, "SSH blacklist"),
    (SSH_ACCESS_SCRIPT, "SSH access control script"),
    (TIMESYNCD_CONFIG, "systemd-timesyncd configuration"),
)

LOGROTATE_SAMPLE = Path(__file__).resolve().parent / "nn_ids_logrotate"

LOGROTATE_CANDIDATES: Sequence[Path] = (
    Path("/etc/logrotate.d/nn_ids"),
    Path("/etc/logrotate.d/nn-ids"),
    Path("/etc/logrotate.d/nn_ids_health"),
    LOGROTATE_SAMPLE,
)

LOGROTATE_TARGETS: Sequence[Path] = (
    ALERT_REPORT_SOURCE_LOG,
    Path("/var/log/nn_ids_health.log"),
    ALERT_REPORT_LOG,
    Path("/var/log/nn_ids_train.log"),
    PROCESS_MONITOR_ALERT_LOG,
    PORT_MONITOR_ALERT_LOG,
    RESOURCE_MONITOR_LOG,
)

LOGROTATE_STATE_CANDIDATES: Sequence[Path] = (
    Path("/var/lib/logrotate/status"),
    Path("/var/lib/logrotate/status-uuid"),
)

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

SNAPSHOT_ROOT_CANDIDATES: Sequence[Path] = (
    Path("/var/backups/nnids"),
    Path("/opt/nnids/snapshots"),
    Path("/opt/nnids/backups"),
)
SNAPSHOT_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
SNAPSHOT_STALE_THRESHOLD = timedelta(days=7)
SNAPSHOT_CLOCK_SKEW = timedelta(minutes=10)
SNAPSHOT_VALIDATION_LIMIT = 3
SNAPSHOT_DATASET_ARCHIVE = "datasets.tar.gz"
SNAPSHOT_DATASET_TOP_LEVEL = "datasets"
SNAPSHOT_ARTIFACTS: Sequence[Tuple[str, str, str]] = (
    ("ids_model.pkl", "model.sha256", "model artifact"),
    (SNAPSHOT_DATASET_ARCHIVE, "datasets.sha256", "dataset archive"),
)


@dataclass(frozen=True)
class DiskUsageThreshold:
    candidates: Tuple[Path, ...]
    label: str
    min_free_bytes: int
    min_free_percent: float


@dataclass(frozen=True)
class InodeUsageThreshold:
    candidates: Tuple[Path, ...]
    label: str
    min_free_inodes: int
    min_free_percent: float


@dataclass(frozen=True)
class MemoryUsageThreshold:
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
    DiskUsageThreshold((Path("/"),), "Root filesystem", 5 * 1024**3, 0.10),
    DiskUsageThreshold(
        (Path("/var/log"),),
        "Log storage volume",
        2 * 1024**3,
        0.15,
    ),
    DiskUsageThreshold(
        (Path("/opt/nnids"),),
        "IDS installation volume",
        2 * 1024**3,
        0.10,
    ),
    DiskUsageThreshold(
        tuple(SNAPSHOT_ROOT_CANDIDATES),
        "Snapshot storage",
        5 * 1024**3,
        0.15,
    ),
)


INODE_USAGE_THRESHOLDS: Sequence[InodeUsageThreshold] = (
    InodeUsageThreshold((Path("/"),), "Root filesystem", 20_000, 0.05),
    InodeUsageThreshold(
        (Path("/var/log"),),
        "Log storage volume",
        10_000,
        0.05,
    ),
    InodeUsageThreshold(
        (Path("/opt/nnids"),),
        "IDS installation volume",
        5_000,
        0.05,
    ),
    InodeUsageThreshold(
        tuple(SNAPSHOT_ROOT_CANDIDATES),
        "Snapshot storage",
        5_000,
        0.05,
    ),
)

MEMORY_USAGE_THRESHOLDS: Sequence[MemoryUsageThreshold] = (
    MemoryUsageThreshold(
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

MEMINFO_PATH = Path("/proc/meminfo")
LOADAVG_PATH = Path("/proc/loadavg")
CPU_RUN_QUEUE_MAX_PER_CPU = 1.5

SYSTEMCTL_AVAILABLE = shutil.which("systemctl") is not None
_SYSTEMCTL_WARNING_EMITTED = False
_TIMEDATECTL_WARNING_EMITTED = False


@dataclass(frozen=True)
class UnitStateInfo:
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str
    detail: Optional[str] = None
    properties: Dict[str, str] = field(default_factory=dict)


class LogFileSnapshot(NamedTuple):
    exists: bool
    size: Optional[int]
    regular: bool


class LogrotateBlock(NamedTuple):
    pattern: str
    lines: List[str]


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


def _format_bytes(size: int) -> str:
    suffixes = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(size)
    for suffix in suffixes:
        if value < 1024.0 or suffix == suffixes[-1]:
            return f"{value:.1f} {suffix}" if suffix != "B" else f"{int(value)} {suffix}"
        value /= 1024.0
    return f"{value:.1f} PiB"


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


def _resolve_access_file(
    primary: Path,
    fallbacks: Sequence[Path],
    label: str,
    logger: Callable[[str], None],
) -> Tuple[Optional[Path], bool]:
    """Return a usable access-control file path and whether it is canonical."""

    if primary.exists():
        if not primary.is_file():
            logger(f"{label} {primary} is not a regular file")
            return None, False
        return primary, True

    for candidate in fallbacks:
        if not candidate.exists():
            continue
        if not candidate.is_file():
            logger(f"{label} {candidate} is not a regular file")
            return None, False
        logger(
            f"{label} deployed at {candidate}; relocate it to {primary} for consistent automation"
        )
        return candidate, False

    logger(f"{label} missing ({primary})")
    return None, False


def _load_access_networks(
    path: Path,
    label: str,
    logger: Callable[[str], None],
) -> Tuple[List[ipaddress._BaseNetwork], bool]:
    """Parse IPv4/IPv6 networks from an access-control configuration file."""

    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read {label} {path}: {exc}")
        return [], False

    networks: List[ipaddress._BaseNetwork] = []
    seen: Dict[str, int] = {}
    duplicates: List[str] = []
    invalid: List[str] = []
    healthy = True

    for index, raw_line in enumerate(contents.splitlines(), 1):
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
            healthy = False
            continue

        normalized = str(network)
        if normalized in seen:
            duplicates.append(f"{normalized} (lines {seen[normalized]} & {index})")
            healthy = False
            continue

        seen[normalized] = index
        networks.append(network)

        if network.version != 4:
            logger(
                f"{label} entry {token} is IPv{network.version}; the IPv4 SSH chain will ignore it"
            )
            healthy = False

    if invalid:
        logger(
            f"{label} {path} contains invalid entries: "
            + ", ".join(invalid)
        )
    if duplicates:
        logger(
            f"{label} {path} contains duplicate networks: "
            + ", ".join(sorted(set(duplicates)))
        )

    if networks:
        count = len(networks)
        label_text = "entry" if count == 1 else "entries"
        logger(f"{label} {path} defines {count} CIDR {label_text}")
    else:
        logger(
            f"{label} {path} defines no CIDR entries; ssh_access_control.sh will allow all clients"
        )
        healthy = False

    return networks, healthy


def _query_iptables(
    args: Sequence[str],
) -> Tuple[Optional[List[str]], Optional[str]]:
    """Run ``iptables`` with ``args`` and return the output lines or an error."""

    if IPTABLES_BINARY is None:
        return None, "iptables binary not found"

    command = [IPTABLES_BINARY, *args]
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


def _read_tail_lines(
    path: Path, *, max_bytes: int = 16384
) -> Tuple[List[str], Optional[str]]:
    """Return the trailing lines from ``path`` or an error string."""

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


def _extract_logrotate_patterns(line: str) -> List[str]:
    patterns: List[str] = []
    for token in line.split():
        cleaned = token.strip().strip('"')
        if not cleaned or cleaned == "{":
            continue
        if cleaned.startswith("/"):
            patterns.append(cleaned)
    return patterns


def _parse_logrotate_config(text: str) -> List[LogrotateBlock]:
    blocks: List[LogrotateBlock] = []
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
                        blocks.append(LogrotateBlock(cleaned, list(block_lines)))
                current_patterns = []
                block_lines = []
                in_block = False
                continue
            block_lines.append(stripped)

    return blocks


def _validate_logrotate_block(
    log_path: Path,
    lines: Sequence[str],
    logger: Callable[[str], None],
) -> bool:
    directives: Dict[str, str] = {}
    for entry in lines:
        if not entry or entry.startswith("#"):
            continue
        key = entry.split()[0].lower()
        directives.setdefault(key, entry)

    healthy = True
    for directive in LOGROTATE_REQUIRED_DIRECTIVES:
        if directive not in directives:
            logger(
                f"{log_path} rotation missing '{directive}' directive; update logrotate policy"
            )
            healthy = False

    rotate_line = directives.get("rotate")
    if rotate_line is None:
        logger(f"{log_path} rotation missing 'rotate' directive")
        healthy = False
    else:
        parts = rotate_line.split()
        if len(parts) < 2:
            logger(f"{log_path} rotate directive missing retention count")
            healthy = False
        else:
            try:
                retention = int(parts[1])
            except ValueError:
                logger(
                    f"{log_path} rotate directive has non-numeric retention '{parts[1]}'"
                )
                healthy = False
            else:
                if retention < 3:
                    logger(
                        f"{log_path} rotate retention {retention} too small; increase to avoid log loss"
                    )
                    healthy = False

    create_line = directives.get("create")
    if create_line is None:
        logger(f"{log_path} rotation missing 'create' directive; log files may inherit lax modes")
        healthy = False
    else:
        parts = create_line.split()
        if len(parts) < 4:
            logger(
                f"{log_path} create directive incomplete ({create_line}); include mode, owner, and group"
            )
            healthy = False
        else:
            mode_token = parts[1]
            try:
                mode_value = int(mode_token, 8)
            except ValueError:
                logger(f"{log_path} create mode '{mode_token}' invalid; use octal like 0640")
                healthy = False
            else:
                if mode_value & stat.S_IWOTH:
                    logger(
                        f"{log_path} create mode {mode_token} allows world write; tighten logrotate policy"
                    )
                    healthy = False
                if mode_value & stat.S_IWGRP:
                    logger(
                        f"{log_path} create mode {mode_token} allows group write; tighten logrotate policy"
                    )
                    healthy = False
                if mode_value & (stat.S_IROTH | stat.S_IXOTH):
                    world_access: List[str] = []
                    if mode_value & stat.S_IROTH:
                        world_access.append("read")
                    if mode_value & stat.S_IXOTH:
                        world_access.append("execute")
                    descriptor = "/".join(world_access) if world_access else "access"
                    logger(
                        f"{log_path} create mode {mode_token} grants world {descriptor}; tighten logrotate policy"
                    )
                    healthy = False
            owner = parts[2]
            group = parts[3]
            if owner != "root":
                logger(
                    f"{log_path} create directive owner {owner}; set to root to protect rotated logs"
                )
                healthy = False
            if group not in {"adm", "root"}:
                logger(
                    f"{log_path} create directive group {group}; use adm or root for rotated logs"
                )
                healthy = False

    su_line = directives.get("su")
    if su_line is None:
        logger(
            f"{log_path} rotation missing 'su' directive; add 'su root adm' to drop privileges"
        )
        healthy = False
    else:
        parts = su_line.split()
        if len(parts) < 3:
            logger(
                f"{log_path} su directive incomplete ({su_line}); specify user and group like 'su root adm'"
            )
            healthy = False
        else:
            su_user = parts[1]
            su_group = parts[2]
            if su_user != "root":
                logger(
                    f"{log_path} su directive user {su_user}; set to root to rotate securely"
                )
                healthy = False
            if su_group not in SECURE_LOG_GROUPS:
                logger(
                    f"{log_path} su directive group {su_group}; choose from {sorted(SECURE_LOG_GROUPS)}"
                )
                healthy = False

    olddir_line = directives.get("olddir")
    if olddir_line and not _validate_logrotate_olddir(log_path, olddir_line, logger):
        healthy = False

    if healthy:
        logger(f"{log_path} logrotate policy validated")

    return healthy


SECURE_LOG_GROUPS = {"adm", "root"}


def _validate_logrotate_olddir(
    log_path: Path, directive: str, logger: Callable[[str], None]
) -> bool:
    """Ensure olddir targets keep rotated logs in a secure location."""

    tokenized = directive.split("#", 1)[0].split()
    if len(tokenized) < 2:
        logger(
            f"{log_path} olddir directive incomplete ({directive}); specify an absolute directory"
        )
        return False

    raw_token = _strip_quotes(tokenized[1])
    if not raw_token:
        logger(f"{log_path} olddir directive missing directory ({directive})")
        return False

    olddir_path = Path(raw_token)
    if not olddir_path.is_absolute():
        logger(
            f"{log_path} olddir {olddir_path} is not absolute; rotate logs into a fixed directory"
        )
        return False

    try:
        stat_result = olddir_path.lstat()
    except FileNotFoundError:
        logger(
            f"{log_path} olddir {olddir_path} missing; create the directory with restrictive permissions"
        )
        return False
    except OSError as exc:
        logger(f"Unable to stat {log_path} olddir {olddir_path}: {exc}")
        return False

    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        logger(
            f"{log_path} olddir {olddir_path} is a symbolic link; rotate into a canonical directory"
        )
        return False
    if not stat.S_ISDIR(mode):
        logger(
            f"{log_path} olddir {olddir_path} is not a directory; adjust the logrotate policy"
        )
        return False

    try:
        log_parent_stat = log_path.parent.lstat()
    except OSError as exc:
        logger(
            f"Unable to stat log directory {log_path.parent} while validating olddir {olddir_path}: {exc}"
        )
        return False

    if stat_result.st_dev != log_parent_stat.st_dev:
        logger(
            f"{log_path} olddir {olddir_path} resides on a different filesystem than {log_path.parent};"
            " configure an olddir on the same device so rotations remain atomic"
        )
        return False

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

    ancestor_issues, ancestor_error = _enumerate_insecure_ancestors(
        olddir_path / log_path.name
    )
    if ancestor_error:
        logger(ancestor_error)
        return False
    if ancestor_issues:
        issues.extend(ancestor_issues)

    if issues:
        joined = "; ".join(issues)
        logger(
            f"{log_path} olddir {olddir_path} insecure ({joined}); harden rotated log directory"
        )
        return False

    owner_text = _format_owner(stat_result.st_uid, stat_result.st_gid)
    logger(
        f"{log_path} olddir {olddir_path} secure ({owner_text} {_format_mode(mode)})"
    )
    return True


def _enumerate_insecure_ancestors(log_path: Path) -> Tuple[List[str], Optional[str]]:
    """Return insecure ancestor details or an error message for the path chain."""

    issues: List[str] = []

    for ancestor in log_path.parents:
        if ancestor == log_path.parent:
            continue
        if ancestor == Path(ancestor.anchor):
            break
        try:
            stat_result = ancestor.lstat()
        except OSError as exc:
            return [], f"Unable to stat ancestor directory {ancestor} for {log_path}: {exc}"

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
            issues.append(f"ancestor {ancestor} is a symbolic link")
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


def _validate_log_file_metadata(
    log_path: Path, logger: Callable[[str], None]
) -> bool:
    """Ensure a log file exists with restrictive ownership and permissions."""

    try:
        stat_result = log_path.lstat()
    except FileNotFoundError:
        logger(f"{log_path} not present yet; logrotate will create it after first use")
        return True
    except OSError as exc:
        logger(f"Unable to stat log file {log_path}: {exc}")
        return False

    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        logger(
            f"{log_path} is a symbolic link; enforce rotation on the canonical log file"
        )
        return False
    if not stat.S_ISREG(mode):
        logger(f"{log_path} is not a regular file; investigate the log destination")
        return False

    permissions = stat.S_IMODE(mode)
    owner_text = _format_owner(stat_result.st_uid, stat_result.st_gid)
    issues: List[str] = []

    if permissions & stat.S_IWOTH:
        issues.append("world-writable")
    if permissions & stat.S_IWGRP:
        issues.append("group-writable")
    if permissions & (stat.S_IROTH | stat.S_IXOTH):
        issues.append("world-accessible")

    try:
        owner = pwd.getpwuid(stat_result.st_uid).pw_name
    except KeyError:
        owner = str(stat_result.st_uid)
    try:
        group = grp.getgrgid(stat_result.st_gid).gr_name
    except KeyError:
        group = str(stat_result.st_gid)

    if owner != "root":
        issues.append(f"owner {owner}")
    if group not in SECURE_LOG_GROUPS:
        issues.append(f"group {group}")

    parent = log_path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        logger(f"Unable to stat parent directory {parent} for {log_path}: {exc}")
        return False

    try:
        parent_owner = pwd.getpwuid(parent_stat.st_uid).pw_name
    except KeyError:
        parent_owner = str(parent_stat.st_uid)
    try:
        parent_group = grp.getgrgid(parent_stat.st_gid).gr_name
    except KeyError:
        parent_group = str(parent_stat.st_gid)

    parent_mode = stat.S_IMODE(parent_stat.st_mode)
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

    ancestor_issues, ancestor_error = _enumerate_insecure_ancestors(log_path)
    if ancestor_error:
        logger(ancestor_error)
        return False

    if ancestor_issues:
        issues.extend(ancestor_issues)

    if issues:
        logger(
            f"{log_path} permissions require hardening ({'; '.join(issues)}); adjust log security"
        )
        return False

    logger(f"{log_path} log file secure ({owner_text} {_format_mode(mode)})")
    return True


def _validate_logrotate_state_metadata(
    state_path: Path, logger: Callable[[str], None]
) -> bool:
    """Ensure the logrotate state file and its parents are secured."""

    try:
        stat_result = state_path.lstat()
    except FileNotFoundError:
        logger(f"Logrotate state file missing during metadata check ({state_path})")
        return False
    except OSError as exc:
        logger(f"Unable to stat logrotate state file {state_path}: {exc}")
        return False

    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        logger(
            f"Logrotate state file {state_path} is a symbolic link; replace it with a regular file"
        )
        return False
    if not stat.S_ISREG(mode):
        logger(
            f"Logrotate state file {state_path} is not a regular file; investigate filesystem hygiene"
        )
        return False

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
        logger(f"Unable to stat logrotate state directory {parent}: {exc}")
        return False

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

    ancestor_issues, ancestor_error = _enumerate_insecure_ancestors(state_path)
    if ancestor_error:
        logger(ancestor_error)
        return False
    if ancestor_issues:
        issues.extend(ancestor_issues)

    if issues:
        joined = "; ".join(issues)
        logger(
            f"Logrotate state file {state_path} permissions require hardening ({joined});"
            " restrict access to protect rotation metadata"
        )
        return False

    owner_text = _format_owner(stat_result.st_uid, stat_result.st_gid)
    logger(
        f"Logrotate state file {state_path} secure ({owner_text} {_format_mode(mode)})"
    )
    return True


def _snapshot_log_file(log_path: Path) -> LogFileSnapshot:
    try:
        stat_result = log_path.stat()
    except FileNotFoundError:
        return LogFileSnapshot(False, None, False)
    except OSError:
        return LogFileSnapshot(False, None, False)

    is_regular = stat.S_ISREG(stat_result.st_mode)
    size = stat_result.st_size if is_regular else stat_result.st_size
    return LogFileSnapshot(True, size, is_regular)


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


def _parse_logrotate_state(text: str, logger: Callable[[str], None]) -> Dict[str, datetime]:
    entries: Dict[str, datetime] = {}
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("logrotate state --") or stripped.startswith("#"):
            continue

        if not stripped.startswith('"'):
            logger(f"Unrecognized logrotate state entry on line {lineno}: {stripped!r}")
            continue

        try:
            _, remainder = stripped.split('"', 1)
            path_token, rest = remainder.split('"', 1)
        except ValueError:
            logger(f"Malformed logrotate state entry on line {lineno}: {stripped!r}")
            continue

        timestamp_text = rest.strip()
        if not timestamp_text:
            logger(f"Logrotate state entry missing timestamp for {path_token!r}")
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
                logger(
                    f"Logrotate state entry for {path_token!r} has unrecognized timestamp {timestamp_text!r}"
                )
                continue
            parsed_time = datetime.fromtimestamp(epoch, timezone.utc)

        entries[path_token] = parsed_time

    return entries


def _evaluate_logrotate_state(
    config_path: Path,
    state_candidates: Sequence[Path],
    tracked_logs: Dict[Path, LogFileSnapshot],
    logger: Callable[[str], None],
) -> bool:
    if not tracked_logs:
        return True

    checked: List[Path] = []
    state_path: Optional[Path] = None
    for candidate in state_candidates:
        if candidate in checked:
            continue
        checked.append(candidate)
        if candidate.exists():
            state_path = candidate
            break

    if state_path is None:
        locations = ", ".join(str(path) for path in checked if path)
        logger(
            "Logrotate state file missing; expected logrotate to manage rotations via "
            f"{locations or 'configured state directive'}"
        )
        return False

    state_secure = _validate_logrotate_state_metadata(state_path, logger)

    try:
        contents = state_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read logrotate state file {state_path}: {exc}")
        return False

    entries = _parse_logrotate_state(contents, logger)
    healthy = state_secure
    now = datetime.now(timezone.utc)

    for log_path, snapshot in tracked_logs.items():
        entry = entries.get(str(log_path)) or entries.get(log_path.as_posix())
        exists = snapshot.exists
        size = snapshot.size or 0

        if entry is None:
            if exists and size > 0:
                healthy = False
                logger(
                    f"{log_path} missing from logrotate state {state_path}; run 'logrotate {config_path}'"
                    " to register rotations"
                )
            else:
                logger(
                    f"{log_path} has not been rotated yet; execute logrotate once to initialize state"
                )
            continue

        if entry > now + LOGROTATE_STATE_CLOCK_SKEW:
            skew = entry - now
            healthy = False
            logger(
                f"{log_path} rotation timestamp {entry.isoformat()} is {_format_duration(skew)} ahead"
                " of system clock; verify system time"
            )
            continue

        age = now - entry
        if age > LOGROTATE_ROTATION_STALE and (not exists or size == 0):
            logger(
                f"{log_path} last rotated {_format_duration(age)} ago but log is empty;"
                " confirm logrotate schedule"
            )
        elif age > LOGROTATE_ROTATION_STALE:
            healthy = False
            logger(
                f"{log_path} last rotated {_format_duration(age)} ago; ensure logrotate timer is running"
            )
        else:
            logger(
                f"{log_path} rotation recorded {_format_duration(age)} ago via {state_path}"
            )

    return healthy


def _debug_logrotate_config(config_path: Path, logger: Callable[[str], None]) -> bool:
    binary = shutil.which("logrotate")
    if not binary:
        logger("logrotate binary not available; install logrotate to manage log retention")
        return False

    try:
        with tempfile.NamedTemporaryFile(prefix="nn_ids_logrotate_state_", delete=True) as state_file:
            result = subprocess.run(
                [binary, "--debug", "--state", state_file.name, str(config_path)],
                capture_output=True,
                text=True,
                check=True,
            )
    except subprocess.CalledProcessError as exc:
        logger(
            f"logrotate debug run failed for {config_path}: exit code {exc.returncode}"
        )
        combined = "\n".join(filter(None, [exc.stdout, exc.stderr]))
        for line in (combined.splitlines()[:5] or ["(no debug output)"]):
            logger(f"logrotate debug output: {line}")
        return False
    except FileNotFoundError:
        logger("logrotate binary not available; install logrotate to manage log retention")
        return False
    except OSError as exc:
        logger(f"Unable to execute logrotate for {config_path}: {exc}")
        return False

    issues = []
    for stream in (result.stdout, result.stderr):
        for line in stream.splitlines():
            if "error" in line.lower():
                issues.append(line.strip())

    for entry in issues[:5]:
        logger(f"logrotate debug reported error: {entry}")

    return not issues


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


def _inspect_systemd_timer_schedule(
    info: UnitStateInfo, logger: Callable[[str], None], label: str
) -> bool:
    properties = info.properties or {}
    now = datetime.now(timezone.utc)
    healthy = True

    schedule_raw = (
        properties.get("OnCalendar")
        or properties.get("TimersCalendar")
        or ""
    )
    schedule_clean = " ".join(schedule_raw.split())
    if schedule_clean and schedule_clean.lower() != "n/a":
        logger(f"{label} schedule: {schedule_clean}")
    else:
        logger(f"{label} missing OnCalendar schedule; inspect the unit definition")
        healthy = False

    last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
    if last_trigger is None:
        logger(f"{label} has not triggered yet; run 'systemctl start {label}' to seed the timer")
        healthy = False
    else:
        skew = last_trigger - now
        if skew > LOGROTATE_STATE_CLOCK_SKEW:
            logger(
                f"{label} last trigger {last_trigger.isoformat()} leads the system clock; verify NTP alignment"
            )
            healthy = False
        else:
            age = now - last_trigger
            logger(f"{label} last triggered {_format_duration(age)} ago")
            if age > LOGROTATE_ROTATION_STALE + LOGROTATE_TIMER_GRACE:
                logger(
                    f"{label} last trigger {_format_duration(age)} ago exceeds daily cadence; investigate schedule"
                )
                healthy = False

    next_trigger = _parse_systemd_timestamp(
        properties.get("NextElapseUSecRealtime", "")
    )
    if next_trigger is None:
        logger(
            f"{label} next run unknown; verify the timer configuration with 'systemctl cat {label}'"
        )
        healthy = False
    else:
        delta = next_trigger - now
        if delta < -LOGROTATE_STATE_CLOCK_SKEW:
            logger(
                f"{label} next run scheduled for {next_trigger.isoformat()} which is in the past; reload or restart the timer"
            )
            healthy = False
        else:
            logger(f"{label} next run in {_format_duration(delta)}")
            if delta > LOGROTATE_TIMER_MAX_INTERVAL:
                logger(
                    f"{label} next run in {_format_duration(delta)} exceeds daily cadence; adjust OnCalendar"
                )
                healthy = False

    return healthy


def _check_logrotate_scheduler(logger: Callable[[str], None]) -> bool:
    """Ensure logrotate executes on a recurring schedule."""

    healthy = True
    timer_ok = False
    cron_ok = False

    if _systemctl_available(logger):
        timer_info = query_unit_state(
            LOGROTATE_TIMER_UNIT,
            (
                "LastTriggerUSec",
                "NextElapseUSecRealtime",
                "OnCalendar",
                "TimersCalendar",
            ),
        )
        if timer_info is None:
            logger("Unable to query logrotate.timer state; systemctl show returned no data")
        else:
            load_state = (timer_info.load_state or "").lower()
            unit_file_state = (timer_info.unit_file_state or "").lower()
            status_text = format_unit_status(timer_info)
            if load_state != "loaded":
                healthy = False
                if load_state == "not-found":
                    logger(
                        "logrotate.timer missing from systemd; install the logrotate package or deploy the unit file"
                    )
                elif load_state == "masked":
                    logger("logrotate.timer is masked; run 'systemctl unmask logrotate.timer'")
                else:
                    detail = f" ({timer_info.detail})" if timer_info.detail else ""
                    logger(
                        f"logrotate.timer load state {load_state or 'unknown'}{detail}; investigate systemd configuration"
                    )
            elif unit_file_state == "masked":
                healthy = False
                logger("logrotate.timer unit file masked; run 'systemctl unmask logrotate.timer'")
            else:
                enabled, enable_state = unit_enabled(LOGROTATE_TIMER_UNIT)
                enable_state = (enable_state or "").lower()
                active_state = (timer_info.active_state or "").lower()
                if active_state in {"active", "activating"} and (
                    enabled or enable_state in UNIT_ALLOWED_ENABLE_STATES
                ):
                    timer_ok = True
                    logger(
                        f"logrotate.timer {status_text}; systemd will trigger scheduled rotations"
                    )
                    if enable_state and enable_state not in UNIT_AUTO_START_STATES:
                        logger(
                            f"logrotate.timer enabled state {enable_state}; confirm persistence across reboots"
                        )
                    if not _inspect_systemd_timer_schedule(
                        timer_info, logger, LOGROTATE_TIMER_UNIT
                    ):
                        healthy = False
                else:
                    healthy = False
                    logger(
                        f"logrotate.timer {status_text}; run 'systemctl enable --now logrotate.timer' to schedule rotations"
                    )

        service_info = query_unit_state(LOGROTATE_SERVICE_UNIT)
        if service_info is not None:
            service_load = (service_info.load_state or "").lower()
            if service_load == "masked":
                healthy = False
                logger("logrotate.service is masked; unmask it so the timer can launch rotations")
            elif service_load == "not-found":
                healthy = False
                logger("logrotate.service missing; reinstall the logrotate package")

    cron_path = LOGROTATE_CRON_PATH
    if cron_path.exists():
        if not _check_secure_path(cron_path, "Logrotate cron job", logger):
            healthy = False
        else:
            try:
                stat_result = cron_path.lstat()
            except OSError as exc:
                healthy = False
                logger(f"Unable to stat logrotate cron job {cron_path}: {exc}")
            else:
                permissions = stat.S_IMODE(stat_result.st_mode)
                if not permissions & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    healthy = False
                    logger(
                        f"Logrotate cron job {cron_path} not executable; run 'chmod 755 {cron_path}'"
                    )
                else:
                    cron_ok = True
                    owner = _format_owner(stat_result.st_uid, stat_result.st_gid)
                    mode_text = _format_mode(stat_result.st_mode)
                    logger(
                        f"Logrotate cron job {cron_path} executable ({owner} {mode_text}); cron.daily will trigger rotations"
                    )
    else:
        if timer_ok:
            logger(f"Logrotate cron job {cron_path} not present; relying on systemd timer")

    if not timer_ok and not cron_ok:
        healthy = False
        logger(
            "No logrotate scheduler detected; enable logrotate.timer or install /etc/cron.daily/logrotate"
        )

    return healthy


def _parse_config_file(path: Path) -> Tuple[Dict[str, str], List[str], List[str]]:
    """Parse a simple KEY=VALUE configuration file."""

    data: Dict[str, str] = {}
    duplicates: List[str] = []
    malformed: List[str] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"Unable to read {path}: {exc}") from exc

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


def _load_configuration_snapshot(
    logger: Callable[[str], None]
) -> Tuple[Optional[ConfigurationSnapshot], bool]:
    """Return cached configuration data and whether parsing issues occurred."""

    global _CONFIG_SNAPSHOT, _CONFIG_SNAPSHOT_ERRORS, _CONFIG_SNAPSHOT_LOADED
    if _CONFIG_SNAPSHOT_LOADED:
        return _CONFIG_SNAPSHOT, _CONFIG_SNAPSHOT_ERRORS

    _CONFIG_SNAPSHOT_LOADED = True
    parse_issue = False

    for candidate in CONFIG_CANDIDATES:
        try:
            if candidate.exists():
                data, duplicates, malformed = _parse_config_file(candidate)
                _CONFIG_SNAPSHOT = ConfigurationSnapshot(
                    path=candidate,
                    data=data,
                    duplicates=duplicates,
                    malformed=malformed,
                )
                _CONFIG_SNAPSHOT_ERRORS = parse_issue
                return _CONFIG_SNAPSHOT, _CONFIG_SNAPSHOT_ERRORS
        except RuntimeError as exc:
            logger(str(exc))
            parse_issue = True

    _CONFIG_SNAPSHOT = None
    _CONFIG_SNAPSHOT_ERRORS = parse_issue
    return _CONFIG_SNAPSHOT, _CONFIG_SNAPSHOT_ERRORS


def _systemctl_available(logger: Callable[[str], None]) -> bool:
    """Log a warning once when systemctl is unavailable."""

    global _SYSTEMCTL_WARNING_EMITTED
    if SYSTEMCTL_AVAILABLE:
        return True
    if not _SYSTEMCTL_WARNING_EMITTED:
        logger("systemctl not available; skipping unit checks")
        _SYSTEMCTL_WARNING_EMITTED = True
    return False


def _timedatectl_available(logger: Callable[[str], None]) -> bool:
    """Log a warning once when timedatectl is unavailable."""

    global _TIMEDATECTL_WARNING_EMITTED
    if TIMEDATECTL_PATH is not None:
        return True
    if not _TIMEDATECTL_WARNING_EMITTED:
        logger(
            "timedatectl not available; falling back to chronyc tracking when possible"
        )
        _TIMEDATECTL_WARNING_EMITTED = True
    return False


def _run_timedatectl(
    args: Sequence[str], logger: Callable[[str], None]
) -> Optional[str]:
    """Execute ``timedatectl`` with ``args`` and return stdout when successful."""

    if TIMEDATECTL_PATH is None:
        return None

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
        logger(f"Unable to execute {' '.join(command)}: {exc}")
        return None

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if not detail:
            detail = f"exit code {result.returncode}"
        logger(f"timedatectl {' '.join(args)} failed: {detail}")
        return None

    return result.stdout or ""


def _parse_key_value_output(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _timedatectl_show(logger: Callable[[str], None]) -> Optional[Dict[str, str]]:
    output = _run_timedatectl(["show"], logger)
    if output is None:
        return None
    return _parse_key_value_output(output)


def _timedatectl_show_timesync(
    logger: Callable[[str], None]
) -> Optional[Dict[str, str]]:
    output = _run_timedatectl(["show-timesync"], logger)
    if output is None:
        return None
    return _parse_key_value_output(output)


def _collect_chronyc_tracking(
    logger: Callable[[str], None], *, log_errors: bool
) -> Optional[Dict[str, str]]:
    """Return ``chronyc tracking`` key/value output when available."""

    if CHRONYC_PATH is None:
        return None

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
        if log_errors:
            logger(f"Unable to execute {' '.join(command)}: {exc}")
        return None

    if result.returncode != 0:
        if log_errors:
            detail = (result.stderr or result.stdout or "").strip()
            if not detail:
                detail = f"exit code {result.returncode}"
            logger(f"chronyc tracking failed: {detail}")
        return None

    data: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


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


def query_unit_state(
    unit: str, extra_properties: Sequence[str] = ()
) -> Optional[UnitStateInfo]:
    """Return systemd state details for ``unit`` when available."""

    if not SYSTEMCTL_AVAILABLE:
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
        detail = str(exc)
        return UnitStateInfo("error", "", "", "", detail)

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


def format_unit_status(info: Optional[UnitStateInfo]) -> str:
    """Return a readable status string for a systemd unit."""

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


def check_services(
    logger: Callable[[str], None], restart: bool = True
) -> bool:
    """Check that critical services are active, restarting when requested."""

    if not _systemctl_available(logger):
        return True

    healthy = True
    for unit, description in CRITICAL_SERVICES:
        state = query_unit_state(unit)
        if state is not None:
            load_state = state.load_state.lower()
            if load_state != "loaded":
                healthy = False
                if load_state == "not-found":
                    logger(
                        f"{description} ({unit}) missing from systemd; reinstall or deploy the unit file"
                    )
                elif load_state == "masked":
                    logger(
                        f"{description} ({unit}) is masked; unmask the unit so the service can start"
                    )
                else:
                    detail = f" ({state.detail})" if state.detail else ""
                    logger(
                        f"{description} ({unit}) load state {load_state or 'unknown'}{detail};"
                        " investigate systemd configuration"
                    )
                if state.unit_file_state.lower() == "masked":
                    logger(
                        f"{description} ({unit}) unit file state masked; run 'systemctl unmask {unit}'"
                    )
                continue
            if state.unit_file_state.lower() == "masked":
                healthy = False
                logger(
                    f"{description} ({unit}) unit file is masked; unmask to allow startups"
                )
                continue
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
        state = query_unit_state(unit)
        if state is not None:
            load_state = state.load_state.lower()
            if load_state != "loaded":
                healthy = False
                if load_state == "not-found":
                    logger(
                        f"{description} ({unit}) missing from systemd; reinstall or restore the timer unit"
                    )
                elif load_state == "masked":
                    logger(
                        f"{description} ({unit}) is masked; unmask it so scheduled jobs resume"
                    )
                else:
                    detail = f" ({state.detail})" if state.detail else ""
                    logger(
                        f"{description} ({unit}) load state {load_state or 'unknown'}{detail};"
                        " investigate timer configuration"
                    )
                if state.unit_file_state.lower() == "masked":
                    logger(
                        f"{description} ({unit}) unit file state masked; run 'systemctl unmask {unit}'"
                    )
                continue
            if state.unit_file_state.lower() == "masked":
                healthy = False
                logger(
                    f"{description} ({unit}) unit file is masked; unmask to allow scheduling"
                )
                continue
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
    for unit_group in (CRITICAL_SERVICES, CRITICAL_TIMERS):
        for unit, description in unit_group:
            if unit in checked:
                continue
            checked.add(unit)
            enabled, state = unit_enabled(unit)
            state_lower = state.lower()
            if enabled or state_lower in UNIT_ALLOWED_ENABLE_STATES:
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


def _parse_snapshot_timestamp(name: str) -> Optional[datetime]:
    try:
        parsed = datetime.strptime(name, SNAPSHOT_TIMESTAMP_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _read_snapshot_hash(
    snapshot_name: str,
    hash_path: Path,
    label: str,
    logger: Callable[[str], None],
) -> Optional[str]:
    try:
        text = hash_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger(
            f"Snapshot {snapshot_name} {label} hash unreadable ({hash_path}): {exc}"
        )
        return None

    token = text.split()[0] if text else ""
    if len(token) != 64:
        descriptor = token or "(empty)"
        logger(
            f"Snapshot {snapshot_name} {label} hash {descriptor!r} invalid; expected 64 hex characters"
        )
        return None

    try:
        int(token, 16)
    except ValueError:
        logger(
            f"Snapshot {snapshot_name} {label} hash {token!r} contains non-hex characters"
        )
        return None

    return token.lower()


def _validate_snapshot_dataset_archive(
    snapshot_name: str,
    archive_path: Path,
    logger: Callable[[str], None],
) -> bool:
    """Ensure the dataset archive is readable and contains safe members."""

    try:
        with tarfile.open(archive_path, "r:gz") as handle:
            try:
                members = handle.getmembers()
            except tarfile.TarError as exc:
                logger(
                    f"Snapshot {snapshot_name} unable to enumerate {archive_path}: {exc}"
                )
                return False
    except (tarfile.TarError, OSError) as exc:
        logger(
            f"Snapshot {snapshot_name} dataset archive {archive_path} unreadable: {exc}"
        )
        return False

    if not members:
        logger(
            f"Snapshot {snapshot_name} dataset archive {archive_path} empty; confirm snapshot captured datasets"
        )
        return False

    healthy = True
    top_level: Set[str] = set()
    file_count = 0

    for member in members:
        name = member.name
        normalized = Path(name)

        if normalized.is_absolute() or any(part in {"..", ""} for part in normalized.parts):
            logger(
                f"Snapshot {snapshot_name} dataset archive {archive_path} contains unsafe member {name!r}; recreate the snapshot"
            )
            healthy = False

        if member.issym() or member.islnk():
            logger(
                f"Snapshot {snapshot_name} dataset archive {archive_path} embeds link {name!r}; links are unsupported"
            )
            healthy = False

        if member.ischr() or member.isblk() or member.isfifo():
            logger(
                f"Snapshot {snapshot_name} dataset archive {archive_path} embeds special file {name!r}; prune the archive"
            )
            healthy = False

        if member.isfile():
            file_count += 1

        parts = normalized.parts
        if parts:
            top_level.add(parts[0])

    if top_level != {SNAPSHOT_DATASET_TOP_LEVEL}:
        expected = SNAPSHOT_DATASET_TOP_LEVEL
        logger(
            f"Snapshot {snapshot_name} dataset archive {archive_path} top-level entries {sorted(top_level)}; expected only '{expected}'"
        )
        healthy = False

    if file_count == 0:
        logger(
            f"Snapshot {snapshot_name} dataset archive {archive_path} contains no regular files; verify dataset capture"
        )
        healthy = False
    else:
        logger(
            f"Snapshot {snapshot_name} dataset archive contains {file_count} files under {SNAPSHOT_DATASET_TOP_LEVEL}"
        )

    return healthy


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


def _extract_string_list(
    data: Dict[str, object],
    key: str,
    label: str,
    logger: Callable[[str], None],
    *,
    required: bool,
    max_entries: int,
) -> Tuple[List[str], bool]:
    """Pull a list of strings from a payload while normalizing and validating entries."""

    value = data.get(key)
    if value is None:
        if required:
            logger(f"{label} list missing from payload")
            return [], False
        return [], True

    if not isinstance(value, list):
        logger(f"{label} list has unexpected type {type(value).__name__}")
        return [], False

    healthy = True
    sanitized: List[str] = []
    seen: Set[str] = set()
    duplicates: Set[str] = set()

    if len(value) > max_entries:
        logger(f"{label} list contains {len(value)} entries; trimming may have failed")
        healthy = False

    for index, entry in enumerate(value):
        if not isinstance(entry, str):
            logger(
                f"{label} entry {index} has invalid type {type(entry).__name__}; expected string"
            )
            healthy = False
            continue
        candidate = entry.strip()
        if not candidate:
            logger(f"{label} entry {index} is empty or whitespace-only")
            healthy = False
            continue
        sanitized.append(candidate)
        if candidate in seen:
            duplicates.add(candidate)
        seen.add(candidate)

    if duplicates:
        logger(
            f"{label} list contains duplicates: "
            + ", ".join(sorted(duplicates))
        )
        healthy = False

    if sanitized and sanitized != sorted(sanitized):
        logger(f"{label} list is not sorted; baseline serialization may be inconsistent")
        healthy = False

    return sanitized, healthy


def _extract_int_list(
    value: object,
    label: str,
    logger: Callable[[str], None],
    *,
    max_entries: int,
    minimum: int,
    maximum: int,
    require_sorted: bool = True,
) -> Tuple[List[int], bool]:
    """Normalize and validate a list of integer values."""

    if not isinstance(value, list):
        logger(f"{label} has unexpected type {type(value).__name__}; expected list")
        return [], False

    healthy = True
    sanitized: List[int] = []
    seen: Set[int] = set()
    duplicates: Set[int] = set()

    if len(value) > max_entries:
        logger(f"{label} contains {len(value)} entries; trimming may have failed")
        healthy = False

    for index, entry in enumerate(value):
        if isinstance(entry, bool) or not isinstance(entry, int):
            logger(
                f"{label} entry {index} has invalid type {type(entry).__name__}; expected integer"
            )
            healthy = False
            continue
        number = int(entry)
        if number < minimum or number > maximum:
            logger(
                f"{label} entry {index} has out-of-range value {number}; expected between"
                f" {minimum} and {maximum}"
            )
            healthy = False
            continue
        sanitized.append(number)
        if number in seen:
            duplicates.add(number)
        seen.add(number)

    if duplicates:
        logger(
            f"{label} contains duplicates: " + ", ".join(str(number) for number in sorted(duplicates))
        )
        healthy = False

    if require_sorted and sanitized and sanitized != sorted(sanitized):
        logger(f"{label} is not sorted; serialization may be stale")
        healthy = False

    return sanitized, healthy


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


def check_configuration_integrity(logger: Callable[[str], None]) -> bool:
    """Validate IDS configuration values for sane and supported settings."""

    healthy = True

    snapshot, parse_issue = _load_configuration_snapshot(logger)
    if parse_issue:
        healthy = False

    if snapshot is None:
        locations = ", ".join(str(path) for path in CONFIG_CANDIDATES)
        logger(f"IDS configuration missing; expected one of: {locations}")
        return False

    config_path = snapshot.path
    config_data = snapshot.data
    duplicate_lines = snapshot.duplicates
    malformed_lines = snapshot.malformed

    if malformed_lines:
        healthy = False
        for detail in malformed_lines:
            logger(f"Configuration parse issue in {config_path}: {detail}")

    if duplicate_lines:
        healthy = False
        for detail in duplicate_lines:
            logger(f"Duplicate configuration key in {config_path}: {detail}")

    bool_values: Dict[str, bool] = {}
    for key, label in CONFIG_BOOL_FIELDS.items():
        raw_value = config_data.get(key)
        if raw_value is None:
            logger(f"{label} ({key}) missing; default may be unsafe")
            healthy = False
            continue
        if raw_value not in {"0", "1"}:
            logger(f"{label} ({key}) invalid value {raw_value!r}; expected 0 or 1")
            healthy = False
            continue
        bool_values[key] = raw_value == "1"
        state = "enabled" if bool_values[key] else "disabled"
        logger(f"{label} ({key}) {state}")

    float_values: Dict[str, float] = {}
    for key, (label, minimum, maximum) in CONFIG_FLOAT_FIELDS.items():
        raw_value = config_data.get(key)
        if raw_value is None:
            logger(f"{label} ({key}) missing; set within [{minimum}, {maximum}]")
            healthy = False
            continue
        try:
            number = float(raw_value)
        except (TypeError, ValueError):
            logger(f"{label} ({key}) not numeric ({raw_value!r})")
            healthy = False
            continue
        if not (minimum <= number <= maximum):
            logger(f"{label} ({key}) {number:.3f} outside [{minimum}, {maximum}]")
            healthy = False
            continue
        float_values[key] = number
        logger(f"{label} ({key}) {number:.3f}")

    int_values: Dict[str, int] = {}
    for key, (label, minimum, maximum) in CONFIG_INT_FIELDS.items():
        raw_value = config_data.get(key)
        if raw_value is None:
            logger(f"{label} ({key}) missing; configure within [{minimum}, {maximum}]")
            healthy = False
            continue
        try:
            number = int(raw_value)
        except (TypeError, ValueError):
            logger(f"{label} ({key}) not an integer ({raw_value!r})")
            healthy = False
            continue
        if not (minimum <= number <= maximum):
            logger(f"{label} ({key}) {number} outside [{minimum}, {maximum}]")
            healthy = False
            continue
        int_values[key] = number
        logger(f"{label} ({key}) {number}")

    discovery_mode = config_data.get(CONFIG_DISCOVERY_KEY)
    if discovery_mode is None:
        logger(
            f"Discovery mode ({CONFIG_DISCOVERY_KEY}) missing; choose one of {sorted(CONFIG_DISCOVERY_MODES)}"
        )
        healthy = False
    else:
        normalized = discovery_mode.lower()
        if normalized not in CONFIG_DISCOVERY_MODES:
            logger(
                f"Discovery mode ({CONFIG_DISCOVERY_KEY}) invalid value {discovery_mode!r};"
                f" expected one of {sorted(CONFIG_DISCOVERY_MODES)}"
            )
            healthy = False
        else:
            logger(f"Discovery mode ({CONFIG_DISCOVERY_KEY}) set to {normalized}")

    min_risk = float_values.get("GA_PROC_MIN_RISK")
    threshold = float_values.get("GA_PROC_THRESHOLD")
    if min_risk is not None and threshold is not None and min_risk < threshold:
        logger(
            "GA Tech process minimum risk (GA_PROC_MIN_RISK) below GA_PROC_THRESHOLD;"
            " adjust to avoid suppressing process alerts"
        )
        healthy = False

    if SYSTEMCTL_AVAILABLE:
        for key, (feature_label, dependencies) in CONFIG_FEATURE_DEPENDENCIES.items():
            if key not in bool_values or not dependencies:
                continue
            enabled_flag = bool_values[key]
            dependency_issue = False
            status_details: List[Tuple[str, str, str, str]] = []
            for dependency in dependencies:
                unit = dependency.unit
                description = dependency.description
                info = query_unit_state(unit)
                load_state = (info.load_state.lower() if info else "")
                unit_file_state = (info.unit_file_state.lower() if info else "")
                status_text = format_unit_status(info)
                enabled_state, state = unit_enabled(unit)
                state_lower = state.lower()
                status_details.append(
                    (
                        description,
                        status_text,
                        state_lower or "unknown",
                        load_state or "loaded",
                    )
                )

                if info is not None and load_state != "loaded":
                    dependency_issue = True
                    healthy = False
                    if load_state == "not-found":
                        logger(
                            f"{feature_label} ({key}) dependency {description} ({unit}) missing; reinstall the unit"
                        )
                    elif load_state == "masked":
                        logger(
                            f"{feature_label} ({key}) dependency {description} ({unit}) is masked; unmask it"
                        )
                    else:
                        detail = f" ({info.detail})" if info.detail else ""
                        logger(
                            f"{feature_label} ({key}) dependency {description} ({unit}) load state {load_state or 'unknown'}{detail}"
                        )
                    if unit_file_state == "masked":
                        logger(
                            f"{feature_label} ({key}) dependency {description} ({unit}) unit file masked; run 'systemctl unmask {unit}'"
                        )
                    continue

                if unit_file_state == "masked":
                    dependency_issue = True
                    healthy = False
                    logger(
                        f"{feature_label} ({key}) dependency {description} ({unit}) unit file is masked; unmask it"
                    )
                    continue

                normalized_status = (info.active_state.lower() if info and info.active_state else "")

                if dependency.kind == DEPENDENCY_KIND_TIMER:
                    if enabled_flag:
                        if normalized_status not in {"active", "activating"}:
                            dependency_issue = True
                            healthy = False
                            logger(
                                f"{feature_label} ({key}) enabled but {description} ({unit}) {status_text}; start or enable the timer"
                            )
                        if not (
                            enabled_state or state_lower in UNIT_ALLOWED_ENABLE_STATES
                        ):
                            dependency_issue = True
                            healthy = False
                            logger(
                                f"{feature_label} ({key}) enabled but {description} ({unit}) not enabled for startup"
                                f" (state: {state_lower or 'disabled'}); enable it or mask intentionally"
                            )
                    else:
                        if normalized_status in {"active", "activating"}:
                            dependency_issue = True
                            healthy = False
                            logger(
                                f"{feature_label} ({key}) disabled but {description} ({unit}) still {status_text}; disable the timer or update {key}"
                            )
                        if enabled_state or state_lower in UNIT_AUTO_START_STATES:
                            dependency_issue = True
                            healthy = False
                            logger(
                                f"{feature_label} ({key}) disabled but {description} ({unit}) remains enabled"
                                f" (state: {state_lower or 'enabled'}); disable it to prevent unintended automation"
                            )
                else:  # service dependency
                    if enabled_flag and normalized_status == "failed":
                        dependency_issue = True
                        healthy = False
                        logger(
                            f"{feature_label} ({key}) enabled but {description} ({unit}) failed; inspect logs"
                        )
                    if not enabled_flag and normalized_status in {"active", "activating", "running"}:
                        dependency_issue = True
                        healthy = False
                        logger(
                            f"{feature_label} ({key}) disabled but {description} ({unit}) running; stop the service or update {key}"
                        )
                    if state_lower.startswith("error"):
                        dependency_issue = True
                        healthy = False
                        logger(
                            f"Unable to determine enablement for {description} ({unit}): {state_lower}"
                        )

            if not dependency_issue:
                state_text = "enabled" if enabled_flag else "disabled"
                summary_parts = []
                for desc, status_text, enable_state, load_state in status_details:
                    annotations: List[str] = []
                    if load_state and load_state not in {"loaded", ""}:
                        annotations.append(f"load={load_state}")
                    if enable_state:
                        annotations.append(f"enablement={enable_state}")
                    annotation_text = f" ({', '.join(annotations)})" if annotations else ""
                    summary_parts.append(f"{desc} {status_text}{annotation_text}")
                summary = ", ".join(summary_parts)
                logger(f"{feature_label} ({key}) {state_text}; {summary}")
    else:
        for key, (feature_label, dependencies) in CONFIG_FEATURE_DEPENDENCIES.items():
            if key in bool_values and bool_values[key] and dependencies:
                logger(
                    f"{feature_label} ({key}) enabled but unable to verify supporting units",
                    " because systemctl is unavailable",
                )

    if healthy:
        logger(f"Configuration integrity verified using {config_path}")

    return healthy


def check_process_monitor_state(logger: Callable[[str], None]) -> bool:
    """Validate the process monitor baseline and supporting artifacts."""

    baseline = PROCESS_MONITOR_BASELINE
    if not baseline.exists():
        logger(
            f"Process monitor baseline missing at {baseline}; ensure process_monitor.timer has run"
        )
        return False

    if not baseline.is_file():
        logger(f"Process monitor baseline {baseline} is not a regular file")
        return False

    healthy = True

    if not _check_secure_path(
        baseline.parent, "Process monitor state directory", logger
    ):
        healthy = False
    if not _check_secure_path(baseline, "Process monitor baseline", logger):
        healthy = False

    try:
        raw = baseline.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read process monitor baseline {baseline}: {exc}")
        return False

    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        logger(f"Process monitor baseline {baseline} contains invalid JSON")
        return False

    if not isinstance(payload, dict):
        logger(
            f"Process monitor baseline {baseline} has unexpected structure; expected JSON object"
        )
        return False

    processes, processes_ok = _extract_string_list(
        payload,
        "processes",
        "Process monitor processes",
        logger,
        required=True,
        max_entries=PROCESS_MONITOR_MAX_PROCESSES,
    )
    services, services_ok = _extract_string_list(
        payload,
        "services",
        "Process monitor services",
        logger,
        required=True,
        max_entries=PROCESS_MONITOR_MAX_SERVICES,
    )

    healthy &= processes_ok and services_ok

    if not processes:
        logger(
            "Process monitor baseline contains no processes; refresh the baseline by running process_monitor.service"
        )
        healthy = False

    if not services:
        logger(
            "Process monitor baseline contains no services; ensure process_monitor.service captures systemd state"
        )
        healthy = False

    now = datetime.now(timezone.utc)
    try:
        stat_result = baseline.stat()
    except OSError as exc:
        logger(f"Unable to stat process monitor baseline {baseline}: {exc}")
        return False

    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > PROCESS_MONITOR_CLOCK_SKEW:
        logger(
            "Process monitor baseline timestamp"
            f" {mtime.isoformat()} is {_format_duration(skew)} ahead of the system clock; verify time synchronization"
        )
        healthy = False
    else:
        age = now - mtime
        logger(
            f"Process monitor baseline tracks {len(processes)} processes and {len(services)} services;"
            f" updated {_format_duration(age)} ago"
        )
        if age > PROCESS_MONITOR_STALE_THRESHOLD:
            logger(
                "Process monitor baseline older than"
                f" {_format_duration(PROCESS_MONITOR_STALE_THRESHOLD)}; ensure process_monitor.timer is active"
            )
            healthy = False

    optional_paths = (
        (PROCESS_MONITOR_ALERT_LOG, "Process monitor alert log"),
        (PROCESS_MONITOR_ACTIVITY_LOG, "Process monitor activity log"),
    )

    for path, label in optional_paths:
        if not path.exists():
            logger(f"{label} not found at {path}; it will be created when alerts occur")
            continue
        if not path.is_file():
            logger(f"{label} {path} is not a regular file")
            healthy = False
            continue
        if not _check_secure_path(path, label, logger):
            healthy = False
            continue
        try:
            stat_result = path.stat()
        except OSError as exc:
            logger(f"Unable to stat {label.lower()} {path}: {exc}")
            healthy = False
            continue
        age = now - datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
        logger(f"{label} updated {_format_duration(age)} ago")

    return healthy


def check_port_monitor_state(logger: Callable[[str], None]) -> bool:
    """Validate the port monitor baseline and alert log."""

    baseline = PORT_MONITOR_BASELINE
    if not baseline.exists():
        logger(
            f"Port monitor baseline missing at {baseline}; ensure port_socket_monitor.timer has run"
        )
        return False

    if not baseline.is_file():
        logger(f"Port monitor baseline {baseline} is not a regular file")
        return False

    healthy = True

    if not _check_secure_path(baseline.parent, "Port monitor state directory", logger):
        healthy = False
    if not _check_secure_path(baseline, "Port monitor baseline", logger):
        healthy = False

    try:
        raw = baseline.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read port monitor baseline {baseline}: {exc}")
        return False

    try:
        payload = json.loads(raw or "[]")
    except json.JSONDecodeError:
        logger(f"Port monitor baseline {baseline} contains invalid JSON")
        return False

    ports, ports_ok = _extract_int_list(
        payload,
        "Port monitor baseline",
        logger,
        max_entries=PORT_MONITOR_MAX_PORTS,
        minimum=1,
        maximum=65535,
    )
    healthy &= ports_ok

    if not ports:
        logger(
            "Port monitor baseline lists no listening ports; verify baseline capture before clearing alerts"
        )
        healthy = False

    try:
        stat_result = baseline.stat()
    except OSError as exc:
        logger(f"Unable to stat port monitor baseline {baseline}: {exc}")
        return False

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > PORT_MONITOR_CLOCK_SKEW:
        logger(
            "Port monitor baseline timestamp"
            f" {mtime.isoformat()} is {_format_duration(skew)} ahead of the system clock; verify time synchronization"
        )
        healthy = False
    else:
        age = now - mtime
        logger(
            f"Port monitor baseline tracks {len(ports)} listening ports; updated {_format_duration(age)} ago"
        )
        if age > PORT_MONITOR_STALE_THRESHOLD:
            logger(
                "Port monitor baseline older than"
                f" {_format_duration(PORT_MONITOR_STALE_THRESHOLD)}; ensure port_socket_monitor.timer is active"
            )
            healthy = False

    if PORT_MONITOR_ALERT_LOG.exists():
        if not PORT_MONITOR_ALERT_LOG.is_file():
            logger(f"Port monitor alert log {PORT_MONITOR_ALERT_LOG} is not a regular file")
            healthy = False
        elif not _check_secure_path(PORT_MONITOR_ALERT_LOG, "Port monitor alert log", logger):
            healthy = False
        else:
            try:
                alert_stat = PORT_MONITOR_ALERT_LOG.stat()
            except OSError as exc:
                logger(f"Unable to stat port monitor alert log {PORT_MONITOR_ALERT_LOG}: {exc}")
                healthy = False
            else:
                age = now - datetime.fromtimestamp(alert_stat.st_mtime, timezone.utc)
                logger(
                    f"Port monitor alert log updated {_format_duration(age)} ago"
                    f" ({PORT_MONITOR_ALERT_LOG})"
                )
    else:
        logger(
            f"Port monitor alert log not found at {PORT_MONITOR_ALERT_LOG}; it will be created on first alert"
        )

    if healthy:
        logger(f"Port monitor baseline validated via {baseline}")

    return healthy


def check_network_io_monitor(logger: Callable[[str], None]) -> bool:
    """Validate network I/O logging rules, rotation, and log freshness."""

    healthy = True
    now = datetime.now(timezone.utc)

    rsyslog_path = NETWORK_IO_RSYSLOG_CONF
    if not rsyslog_path.exists():
        logger(
            f"Network I/O rsyslog rules missing at {rsyslog_path}; run {NETWORK_IO_SERVICE}"
            " to deploy logging directives"
        )
        healthy = False
    elif not rsyslog_path.is_file():
        logger(f"Network I/O rsyslog configuration {rsyslog_path} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(
            rsyslog_path, "Network I/O rsyslog configuration", logger
        ):
            healthy = False
        try:
            rsyslog_contents = rsyslog_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger(
                f"Unable to read network I/O rsyslog configuration {rsyslog_path}: {exc}"
            )
            return False

        missing_rules: List[Tuple[str, Path]] = []
        for prefix, log_path in NETWORK_IO_EXPECTED_RULES:
            if prefix not in rsyslog_contents or str(log_path) not in rsyslog_contents:
                missing_rules.append((prefix.strip(), log_path))

        if missing_rules:
            for label, log_path in missing_rules:
                logger(
                    f"Network I/O rsyslog rules missing {label} mapping to {log_path};"
                    f" rerun {NETWORK_IO_SERVICE} or update {rsyslog_path}"
                )
            healthy = False
        else:
            logger(f"Network I/O rsyslog rules present in {rsyslog_path}")

    logrotate_path = NETWORK_IO_LOGROTATE_CONF
    if not logrotate_path.exists():
        logger(
            "Network I/O logrotate policy missing; run"
            f" {NETWORK_IO_SERVICE} to install {logrotate_path}"
        )
        healthy = False
    elif not logrotate_path.is_file():
        logger(f"Network I/O logrotate policy {logrotate_path} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(
            logrotate_path, "Network I/O logrotate policy", logger
        ):
            healthy = False
        try:
            logrotate_contents = logrotate_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger(
                f"Unable to read network I/O logrotate policy {logrotate_path}: {exc}"
            )
            return False

        blocks = _parse_logrotate_config(logrotate_contents)
        if not blocks:
            logger(
                f"Network I/O logrotate policy {logrotate_path} defines no log targets;"
                " include inbound/outbound traffic logs"
            )
            healthy = False
        for prefix, log_path in NETWORK_IO_EXPECTED_RULES:
            matched: Optional[LogrotateBlock] = None
            for block in blocks:
                if fnmatch.fnmatch(str(log_path), block.pattern):
                    matched = block
                    break
            if matched is None:
                logger(
                    f"{log_path} missing from {logrotate_path}; add a rotation block for"
                    f" {prefix.strip()} traffic"
                )
                healthy = False
                continue
            if not _validate_logrotate_block(log_path, matched.lines, logger):
                healthy = False
            elif not _validate_log_file_metadata(log_path, logger):
                healthy = False

    for prefix, log_path in NETWORK_IO_EXPECTED_RULES:
        label = prefix.strip() or "Network"
        existed = log_path.exists()
        if not existed:
            logger(
                f"{label} log missing at {log_path}; generate traffic or restart"
                f" {NETWORK_IO_SERVICE} to seed logging"
            )
            healthy = False
            continue
        if not log_path.is_file():
            logger(f"{label} log {log_path} is not a regular file")
            healthy = False
            continue

        try:
            stat_result = log_path.stat()
        except OSError as exc:
            logger(f"Unable to stat {label.lower()} log {log_path}: {exc}")
            healthy = False
            continue

        mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
        skew = mtime - now
        if skew > NETWORK_IO_CLOCK_SKEW:
            logger(
                f"{label} log timestamp {mtime.isoformat()} leads system time by"
                f" {_format_duration(skew)}; verify time synchronization"
            )
            healthy = False
            continue

        age = now - mtime
        logger(
            f"{label} log updated {_format_duration(age)} ago ({log_path})"
        )
        if age > NETWORK_IO_STALE_THRESHOLD:
            logger(
                f"{label} log older than"
                f" {_format_duration(NETWORK_IO_STALE_THRESHOLD)}; ensure iptables logging remains active"
            )
            healthy = False

        tail_lines, error = _read_tail_lines(log_path, max_bytes=4096)
        if error:
            logger(error)
            healthy = False
            continue
        if tail_lines:
            recent_lines = tail_lines[-20:]
            if not any(prefix.strip() in line for line in recent_lines):
                logger(
                    f"{label} log tail lacks expected '{prefix.strip()}' prefix;"
                    " confirm rsyslog rules are capturing traffic"
                )
                healthy = False
        elif stat_result.st_size == 0:
            logger(
                f"{label} log empty; verify rsyslog is writing {prefix.strip()} traffic"
            )
            healthy = False

    if _systemctl_available(logger):
        info = query_unit_state(NETWORK_IO_SERVICE)
        if info is None:
            logger(
                "Unable to query network_io_monitor.service; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(info)
            logger(f"Network I/O monitor service status: {status_text}")
            load_state = (info.load_state or "").lower()
            unit_file_state = (info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({info.detail})" if info.detail else ""
                logger(
                    f"Network I/O monitor service load state {load_state or 'unknown'}{detail};"
                    " reinstall or unmask the unit"
                )
                healthy = False
            elif (info.active_state or "").lower() == "failed":
                logger(
                    "Network I/O monitor service failed on its last run; inspect"
                    " journalctl -u network_io_monitor.service"
                )
                healthy = False

            enabled, enable_state = unit_enabled(NETWORK_IO_SERVICE)
            normalized = enable_state.lower()
            if not enabled and normalized not in UNIT_ALLOWED_ENABLE_STATES:
                logger(
                    f"Network I/O monitor service enablement {enable_state}; run"
                    f" 'systemctl enable --now {NETWORK_IO_SERVICE}'"
                )
                healthy = False

    if healthy:
        logger("Network I/O monitor logging verified")

    return healthy


def check_internet_access_monitor(logger: Callable[[str], None]) -> bool:
    """Validate internet access monitoring logs, service, and timer."""

    healthy = True
    now = datetime.now(timezone.utc)
    log_path = INTERNET_ACCESS_LOG

    if not log_path.exists():
        logger(
            f"Internet access monitor log missing at {log_path}; ensure"
            f" {INTERNET_ACCESS_TIMER} has run"
        )
        healthy = False
    elif not log_path.is_file():
        logger(f"Internet access monitor log {log_path} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(log_path, "Internet access log", logger):
            healthy = False
        try:
            stat_result = log_path.stat()
        except OSError as exc:
            logger(f"Unable to stat internet access log {log_path}: {exc}")
            return False

        mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
        skew = mtime - now
        if skew > INTERNET_ACCESS_CLOCK_SKEW:
            logger(
                "Internet access log timestamp"
                f" {mtime.isoformat()} leads system time by"
                f" {_format_duration(skew)}; verify clock synchronization"
            )
            healthy = False
        else:
            age = now - mtime
            logger(
                f"Internet access log updated {_format_duration(age)} ago"
                f" ({log_path})"
            )
            if age > INTERNET_ACCESS_STALE_THRESHOLD:
                logger(
                    "Internet access log older than"
                    f" {_format_duration(INTERNET_ACCESS_STALE_THRESHOLD)}; ensure"
                    f" {INTERNET_ACCESS_TIMER} is active"
                )
                healthy = False

        if stat_result.st_size == 0:
            logger("Internet access log empty; ensure internet_access_monitor.sh is writing entries")
            healthy = False
        else:
            tail_lines, error = _read_tail_lines(log_path, max_bytes=4096)
            if error is not None:
                logger(f"Unable to read internet access log tail: {error}")
                return False

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
                logger(f"Latest internet access verification: {last_success}")
            elif restart_entry:
                logger(
                    "Internet access monitor last entry indicates a restart attempt;"
                    f" {restart_entry}. Investigate connectivity"
                )
                healthy = False
            else:
                logger(
                    "Internet access log tail lacks connectivity verification entries;"
                    f" inspect {INTERNET_ACCESS_SERVICE}"
                )
                healthy = False

    if _systemctl_available(logger):
        service_info = query_unit_state(INTERNET_ACCESS_SERVICE)
        if service_info is None:
            logger(
                "Unable to query internet_access_monitor.service; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(service_info)
            logger(f"Internet access monitor service status: {status_text}")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                logger(
                    "Internet access monitor service load state"
                    f" {load_state or 'unknown'}{detail}; reinstall or unmask the unit"
                )
                healthy = False
            elif (service_info.active_state or "").lower() == "failed":
                logger(
                    "Internet access monitor service failed on its last run; inspect"
                    " journalctl -u internet_access_monitor.service"
                )
                healthy = False

            enabled, enable_state = unit_enabled(INTERNET_ACCESS_SERVICE)
            normalized = enable_state.lower()
            if not enabled and normalized not in UNIT_ALLOWED_ENABLE_STATES:
                logger(
                    "Internet access monitor service not enabled; run"
                    f" 'systemctl enable --now {INTERNET_ACCESS_SERVICE}'"
                )
                healthy = False

        timer_info = query_unit_state(
            INTERNET_ACCESS_TIMER,
            ("OnCalendar", "LastTriggerUSec", "NextElapseUSecRealtime"),
        )
        if timer_info is None:
            logger(
                "Unable to query internet_access_monitor.timer; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(timer_info)
            logger(f"Internet access monitor timer status: {status_text}")
            properties = timer_info.properties or {}
            schedule = properties.get("OnCalendar", "")
            if schedule:
                logger(f"Internet access monitor timer schedule: {schedule}")
            else:
                logger(
                    "Internet access monitor timer missing OnCalendar schedule; inspect the unit definition"
                )
                healthy = False

            active_state = (timer_info.active_state or "").lower()
            enabled, enable_state = unit_enabled(INTERNET_ACCESS_TIMER)
            if active_state in {"active", "activating"}:
                if not enabled and enable_state not in UNIT_ALLOWED_ENABLE_STATES:
                    logger(
                        "Internet access monitor timer not enabled; run"
                        f" 'systemctl enable --now {INTERNET_ACCESS_TIMER}'"
                    )
                    healthy = False
            else:
                logger(
                    "Internet access monitor timer inactive; run"
                    f" 'systemctl enable --now {INTERNET_ACCESS_TIMER}'"
                )
                healthy = False

            last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
            if last_trigger is None:
                logger(
                    f"Internet access monitor timer has not triggered yet; run 'systemctl start {INTERNET_ACCESS_TIMER}'"
                )
                healthy = False
            else:
                skew = last_trigger - now
                if skew > INTERNET_ACCESS_CLOCK_SKEW:
                    logger(
                        "Internet access monitor timer last trigger"
                        f" {last_trigger.isoformat()} is {_format_duration(skew)} ahead of the system clock"
                    )
                    healthy = False
                else:
                    age = now - last_trigger
                    logger(
                        f"Internet access monitor timer last triggered {_format_duration(age)} ago"
                    )
                    if age > INTERNET_ACCESS_STALE_THRESHOLD + INTERNET_ACCESS_TIMER_GRACE:
                        logger(
                            "Internet access monitor timer last trigger exceeds the five-minute cadence; investigate scheduling"
                        )
                        healthy = False

            next_trigger = _parse_systemd_timestamp(
                properties.get("NextElapseUSecRealtime", "")
            )
            if next_trigger is None:
                logger(
                    f"Internet access monitor timer next run unknown; verify the unit with 'systemctl cat {INTERNET_ACCESS_TIMER}'"
                )
                healthy = False
            else:
                delta = next_trigger - now
                if delta < -INTERNET_ACCESS_CLOCK_SKEW:
                    logger(
                        "Internet access monitor timer next run is in the past; restart the timer"
                    )
                    healthy = False
                else:
                    logger(
                        f"Internet access monitor timer next run in {_format_duration(delta)}"
                    )
                    if delta > INTERNET_ACCESS_TIMER_INTERVAL + INTERNET_ACCESS_TIMER_GRACE:
                        logger(
                            "Internet access monitor timer next run exceeds the five-minute cadence; adjust OnUnitActiveSec"
                        )
                        healthy = False

    if healthy:
        logger("Internet access monitoring verified")

    return healthy


def check_alert_reporting(logger: Callable[[str], None]) -> bool:
    """Validate the hourly alert reporting pipeline when notifications are enabled."""

    snapshot, parse_issue = _load_configuration_snapshot(logger)
    healthy = not parse_issue

    if snapshot is None:
        logger("Unable to evaluate alert reporting; IDS configuration is missing")
        return False

    raw_toggle = snapshot.data.get("NN_IDS_NOTIFY")
    if raw_toggle not in {"0", "1"}:
        logger("Notification toggle (NN_IDS_NOTIFY) missing or invalid; expected 0 or 1")
        return False

    if raw_toggle == "0":
        logger("Notification delivery disabled via NN_IDS_NOTIFY; skipping alert reporting validation")
        return healthy

    now = datetime.now(timezone.utc)
    source_log = ALERT_REPORT_SOURCE_LOG
    report_log = ALERT_REPORT_LOG
    state_path = ALERT_REPORT_STATE

    source_size: Optional[int] = None

    if not source_log.exists():
        logger(
            f"Alert source log missing at {source_log}; ensure nn_ids_capture.service is writing alerts"
        )
        return False
    if not source_log.is_file():
        logger(f"Alert source log {source_log} is not a regular file")
        return False
    if not _check_secure_path(source_log, "Alert source log", logger):
        healthy = False
    try:
        source_stat = source_log.stat()
    except OSError as exc:
        logger(f"Unable to stat alert source log {source_log}: {exc}")
        return False
    else:
        source_size = source_stat.st_size
        source_age = now - datetime.fromtimestamp(source_stat.st_mtime, timezone.utc)
        logger(
            f"Alert source log size {_format_bytes(source_size)}; updated {_format_duration(source_age)} ago"
        )

    if not state_path.exists():
        logger(f"Alert report state missing at {state_path}; run {ALERT_REPORT_SERVICE} once")
        return False
    if not state_path.is_file():
        logger(f"Alert report state {state_path} is not a regular file")
        return False
    if not _check_secure_path(state_path, "Alert report state", logger):
        healthy = False

    try:
        state_raw = state_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read alert report state {state_path}: {exc}")
        return False

    try:
        state_payload = json.loads(state_raw or "{}")
    except json.JSONDecodeError as exc:
        logger(f"Alert report state contains invalid JSON: {exc}")
        return False

    if not isinstance(state_payload, dict):
        logger(f"Unexpected structure in {state_path}; expected JSON object")
        return False

    cursor_raw = state_payload.get("pos")
    if isinstance(cursor_raw, bool) or not isinstance(cursor_raw, (int, float)):
        logger(f"Alert report state 'pos' must be an integer; found {type(cursor_raw).__name__}")
        return False

    cursor = int(cursor_raw)
    if cursor < 0:
        logger("Alert report state 'pos' is negative; reset report_state.json")
        return False
    if source_size is not None and cursor > source_size:
        delta = cursor - source_size
        logger(
            "Alert report state cursor"
            f" {cursor} ahead of source log by {_format_bytes(delta)}; rotation bookkeeping may be stale"
        )
        healthy = False

    try:
        state_stat = state_path.stat()
    except OSError as exc:
        logger(f"Unable to stat alert report state {state_path}: {exc}")
        return False

    state_mtime = datetime.fromtimestamp(state_stat.st_mtime, timezone.utc)
    skew = state_mtime - now
    if skew > ALERT_REPORT_CLOCK_SKEW:
        logger(
            f"Alert report state timestamp {state_mtime.isoformat()} is {_format_duration(skew)} ahead of system clock"
        )
        healthy = False
    else:
        state_age = now - state_mtime
        logger(
            "Alert report state cursor"
            f" {cursor} persisted {_format_duration(state_age)} ago"
        )
        if state_age > ALERT_REPORT_STALE_THRESHOLD:
            logger(
                "Alert report state older than"
                f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)}; ensure {ALERT_REPORT_TIMER} is active"
            )
            healthy = False

    if not report_log.exists():
        logger(f"Alert report log missing at {report_log}; run {ALERT_REPORT_SERVICE} to generate summaries")
        healthy = False
    elif not report_log.is_file():
        logger(f"Alert report log {report_log} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(report_log, "Alert report log", logger):
            healthy = False
        try:
            report_stat = report_log.stat()
        except OSError as exc:
            logger(f"Unable to stat alert report log {report_log}: {exc}")
            return False

        report_mtime = datetime.fromtimestamp(report_stat.st_mtime, timezone.utc)
        skew = report_mtime - now
        if skew > ALERT_REPORT_CLOCK_SKEW:
            logger(
                "Alert report log timestamp"
                f" {report_mtime.isoformat()} is {_format_duration(skew)} ahead of system clock"
            )
            healthy = False
        else:
            report_age = now - report_mtime
            logger(
                f"Alert report log updated {_format_duration(report_age)} ago ({report_log})"
            )
            if report_age > ALERT_REPORT_STALE_THRESHOLD:
                logger(
                    "Alert report log older than"
                    f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)};"
                    f" confirm recent alerts are being summarized"
                )
                healthy = False

        tail_lines, error = _read_tail_lines(report_log, max_bytes=4096)
        if error is not None:
            logger(f"Unable to read alert report log tail: {error}")
            return False

        parsed_entries: List[Tuple[datetime, str, int]] = []
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
            candidate_ip = parts[1]
            try:
                ipaddress.ip_address(candidate_ip)
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
            parsed_entries.append((timestamp, candidate_ip, count))

        if malformed:
            logger(
                "Alert report log tail contains"
                f" {malformed} malformed entr{'y' if malformed == 1 else 'ies'}; inspect nn_ids_report.py"
            )
            healthy = False

        if parsed_entries:
            parsed_entries.sort(key=lambda entry: entry[0])
            latest_time, latest_ip, latest_count = parsed_entries[-1]
            skew = latest_time - now
            if skew > ALERT_REPORT_CLOCK_SKEW:
                logger(
                    "Latest alert report entry"
                    f" {latest_time.isoformat()} is {_format_duration(skew)} ahead of system clock"
                )
                healthy = False
            else:
                latest_age = now - latest_time
                logger(
                    f"Latest alert summary captured {_format_duration(latest_age)} ago for {latest_ip}"
                    f" (count {latest_count})"
                )
                if latest_age > ALERT_REPORT_STALE_THRESHOLD:
                    logger(
                        "Latest alert summary older than"
                        f" {_format_duration(ALERT_REPORT_STALE_THRESHOLD)};"
                        f" ensure {ALERT_REPORT_TIMER} is running"
                    )
                    healthy = False

            total_unique = len({entry[1] for entry in parsed_entries})
            total_events = sum(entry[2] for entry in parsed_entries)
            logger(
                f"Parsed {len(parsed_entries)} recent alert summaries covering"
                f" {total_unique} unique IP{'s' if total_unique != 1 else ''}"
                f" across {total_events} event{'s' if total_events != 1 else ''}"
            )
        else:
            logger(
                "Alert report log tail empty; trigger nn_ids_report.service after generating sample alerts"
            )
            healthy = False

    if _systemctl_available(logger):
        service_info = query_unit_state(ALERT_REPORT_SERVICE)
        if service_info is None:
            logger(
                "Unable to query nn_ids_report.service; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(service_info)
            logger(f"Alert report service status: {status_text}")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                logger(
                    "Alert report service load state"
                    f" {load_state or 'unknown'}{detail}; reinstall or unmask the unit"
                )
                healthy = False
            elif (service_info.active_state or "").lower() == "failed":
                logger(
                    "Alert report service failed during its last execution; inspect journalctl -u"
                    f" {ALERT_REPORT_SERVICE}"
                )
                healthy = False

            enabled, enable_state = unit_enabled(ALERT_REPORT_SERVICE)
            normalized = enable_state.lower()
            if not enabled and normalized not in UNIT_ALLOWED_ENABLE_STATES:
                logger(
                    "Alert report service not enabled; run"
                    f" 'systemctl enable --now {ALERT_REPORT_SERVICE}'"
                )
                healthy = False

        timer_info = query_unit_state(
            ALERT_REPORT_TIMER,
            ("OnCalendar", "LastTriggerUSec", "NextElapseUSecRealtime"),
        )
        if timer_info is None:
            logger(
                "Unable to query nn_ids_report.timer; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(timer_info)
            logger(f"Alert report timer status: {status_text}")
            properties = timer_info.properties or {}
            schedule = properties.get("OnCalendar", "")
            if schedule:
                logger(f"Alert report timer schedule: {schedule}")
            else:
                logger(
                    "Alert report timer missing OnCalendar schedule; inspect the unit definition"
                )
                healthy = False

            active_state = (timer_info.active_state or "").lower()
            enabled, enable_state = unit_enabled(ALERT_REPORT_TIMER)
            if active_state in {"active", "activating"}:
                if not enabled and enable_state not in UNIT_ALLOWED_ENABLE_STATES:
                    logger(
                        "Alert report timer not enabled; run"
                        f" 'systemctl enable --now {ALERT_REPORT_TIMER}'"
                    )
                    healthy = False
            else:
                logger(
                    "Alert report timer inactive; run"
                    f" 'systemctl enable --now {ALERT_REPORT_TIMER}'"
                )
                healthy = False

            last_trigger = _parse_systemd_timestamp(properties.get("LastTriggerUSec", ""))
            if last_trigger is None:
                logger(
                    f"Alert report timer has not triggered yet; run 'systemctl start {ALERT_REPORT_TIMER}'"
                )
                healthy = False
            else:
                skew = last_trigger - now
                if skew > ALERT_REPORT_CLOCK_SKEW:
                    logger(
                        "Alert report timer last trigger"
                        f" {last_trigger.isoformat()} is {_format_duration(skew)} ahead of system clock"
                    )
                    healthy = False
                else:
                    age = now - last_trigger
                    logger(
                        f"Alert report timer last triggered {_format_duration(age)} ago"
                    )
                    if age > ALERT_REPORT_TIMER_INTERVAL + ALERT_REPORT_TIMER_GRACE:
                        logger(
                            "Alert report timer last trigger exceeds the hourly cadence; investigate scheduling"
                        )
                        healthy = False

            next_trigger = _parse_systemd_timestamp(
                properties.get("NextElapseUSecRealtime", "")
            )
            if next_trigger is None:
                logger(
                    f"Alert report timer next run unknown; verify the unit with 'systemctl cat {ALERT_REPORT_TIMER}'"
                )
                healthy = False
            else:
                delta = next_trigger - now
                if delta < -ALERT_REPORT_CLOCK_SKEW:
                    logger(
                        "Alert report timer next run is in the past; restart the timer"
                    )
                    healthy = False
                else:
                    logger(
                        f"Alert report timer next run in {_format_duration(delta)}"
                    )
                    if delta > ALERT_REPORT_TIMER_INTERVAL + ALERT_REPORT_TIMER_GRACE:
                        logger(
                            "Alert report timer next run exceeds the hourly cadence; adjust OnCalendar"
                        )
                        healthy = False

    if healthy:
        logger("Alert reporting automation verified")

    return healthy


def check_ssh_access_controls(logger: Callable[[str], None]) -> bool:
    """Validate SSH whitelist/blacklist automation and firewall enforcement."""

    healthy = True

    if not _check_secure_path(SSH_ACCESS_SCRIPT, "SSH access control script", logger):
        healthy = False
    elif not os.access(SSH_ACCESS_SCRIPT, os.X_OK):
        logger(
            f"SSH access control script {SSH_ACCESS_SCRIPT} lacks execute permissions; run chmod +x"
        )
        healthy = False

    whitelist_path, whitelist_primary = _resolve_access_file(
        SSH_WHITELIST_PATH, SSH_WHITELIST_FALLBACKS, "SSH whitelist", logger
    )
    whitelist_networks: List[ipaddress._BaseNetwork] = []
    if whitelist_path is None:
        healthy = False
    else:
        if not whitelist_primary:
            healthy = False
        if not _check_secure_path(whitelist_path, "SSH whitelist", logger):
            healthy = False
        else:
            whitelist_networks, whitelist_ok = _load_access_networks(
                whitelist_path, "SSH whitelist", logger
            )
            if not whitelist_ok:
                healthy = False
            if not whitelist_networks:
                logger(
                    "SSH whitelist empty; automation will accept all SSH clients until populated"
                )
                healthy = False
            for network in whitelist_networks:
                if network.prefixlen == 0:
                    logger(
                        "SSH whitelist includes 0.0.0.0/0; restrict entries to explicit hosts or CIDRs"
                    )
                    healthy = False

    blacklist_path, blacklist_primary = _resolve_access_file(
        SSH_BLACKLIST_PATH, SSH_BLACKLIST_FALLBACKS, "SSH blacklist", logger
    )
    blacklist_networks: List[ipaddress._BaseNetwork] = []
    if blacklist_path is None:
        healthy = False
    else:
        if not blacklist_primary:
            healthy = False
        if not _check_secure_path(blacklist_path, "SSH blacklist", logger):
            healthy = False
        else:
            blacklist_networks, blacklist_ok = _load_access_networks(
                blacklist_path, "SSH blacklist", logger
            )
            if not blacklist_ok:
                healthy = False
            for network in blacklist_networks:
                if network.prefixlen == 0:
                    logger(
                        "SSH blacklist includes 0.0.0.0/0; remove blanket drops to avoid locking operators out"
                    )
                    healthy = False

    if whitelist_networks and blacklist_networks:
        overlaps: List[str] = []
        for allow in whitelist_networks:
            for deny in blacklist_networks:
                if allow.overlaps(deny):
                    overlaps.append(f"{allow} vs {deny}")
        if overlaps:
            logger(
                "SSH whitelist and blacklist overlap: "
                + ", ".join(sorted(set(overlaps)))
            )
            healthy = False

    chain_lines, chain_error = _query_iptables(["-S", SSH_CHAIN_NAME])
    if chain_lines is None:
        logger(
            f"Unable to query iptables chain {SSH_CHAIN_NAME}: {chain_error or 'unknown error'}"
        )
        healthy = False
    else:
        rule_lines = [line for line in chain_lines if line.startswith("-A ")]
        if not rule_lines:
            logger(
                f"iptables chain {SSH_CHAIN_NAME} has no rules; run {SSH_ACCESS_SCRIPT} to apply policies"
            )
            healthy = False
        else:
            logger(
                f"iptables chain {SSH_CHAIN_NAME} includes {len(rule_lines)} rule"
                f"{'s' if len(rule_lines) != 1 else ''}"
            )
            if whitelist_networks:
                drop_present = any(
                    line.startswith(f"-A {SSH_CHAIN_NAME}") and line.endswith("-j DROP")
                    for line in rule_lines
                )
                if not drop_present:
                    logger(
                        f"SSH whitelist populated but {SSH_CHAIN_NAME} lacks a terminating DROP rule"
                        "; rerun ssh_access_control.sh"
                    )
                    healthy = False

    input_lines, input_error = _query_iptables(["-S", "INPUT"])
    if input_lines is None:
        logger(
            "Unable to inspect iptables INPUT chain for SSH enforcement: "
            + (input_error or "unknown error")
        )
        healthy = False
    else:
        hook_found = any(
            line.startswith("-A INPUT")
            and "--dport 22" in line
            and f"-j {SSH_CHAIN_NAME}" in line
            for line in input_lines
        )
        if not hook_found:
            logger(
                f"INPUT chain missing jump to {SSH_CHAIN_NAME} for port 22; run {SSH_ACCESS_SCRIPT}"
            )
            healthy = False
        else:
            logger(f"INPUT chain routes SSH traffic to {SSH_CHAIN_NAME}")

    if healthy:
        logger("SSH access control automation validated")

    return healthy


def check_anti_wipe_monitor(logger: Callable[[str], None]) -> bool:
    """Audit anti-wipe monitoring scripts, dependencies, and logs."""

    healthy = True
    script_path = ANTI_WIPE_SCRIPT
    log_path = ANTI_WIPE_LOG

    if not script_path.exists():
        logger(
            f"Anti-wipe monitor script missing at {script_path}; reinstall host hardening assets"
        )
        healthy = False
    elif not script_path.is_file():
        logger(f"Anti-wipe monitor script {script_path} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(script_path, "Anti-wipe monitor script", logger):
            healthy = False
        try:
            script_stat = script_path.stat()
        except OSError as exc:
            logger(f"Unable to stat anti-wipe monitor script {script_path}: {exc}")
            healthy = False
        else:
            if not script_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                logger(
                    f"Anti-wipe monitor script {script_path} lacks execute permissions; run"
                    " chmod +x"
                )
                healthy = False

    if shutil.which("inotifywait") is None:
        logger("inotifywait binary missing; install inotify-tools for anti-wipe monitoring")
        healthy = False

    if not log_path.exists():
        logger(
            f"Anti-wipe monitor log missing at {log_path}; ensure {ANTI_WIPE_SERVICE} is running"
        )
        healthy = False
    elif not log_path.is_file():
        logger(f"Anti-wipe monitor log {log_path} is not a regular file")
        healthy = False
    else:
        if not _check_secure_path(log_path, "Anti-wipe monitor log", logger):
            healthy = False
        try:
            stat_result = log_path.stat()
        except OSError as exc:
            logger(f"Unable to stat anti-wipe monitor log {log_path}: {exc}")
            healthy = False
        else:
            if stat_result.st_size == 0:
                logger(
                    "Anti-wipe monitor log has no entries yet; trigger a test event to confirm monitoring"
                )
            else:
                tail_lines, error = _read_tail_lines(log_path, max_bytes=2048)
                if error is not None:
                    logger(f"Unable to read anti-wipe monitor log tail: {error}")
                    healthy = False
                else:
                    for raw_line in reversed(tail_lines):
                        stripped = raw_line.strip()
                        if not stripped:
                            continue
                        logger(f"Latest anti-wipe entry: {stripped}")
                        break

    if _systemctl_available(logger):
        service_info = query_unit_state(ANTI_WIPE_SERVICE)
        if service_info is None:
            logger(
                "Unable to query anti_wipe_monitor.service; systemctl show returned no data"
            )
            healthy = False
        else:
            status_text = format_unit_status(service_info)
            logger(f"Anti-wipe monitor service status: {status_text}")
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            if load_state in {"not-found", "masked", "error"} or unit_file_state == "masked":
                detail = f" ({service_info.detail})" if service_info.detail else ""
                logger(
                    "Anti-wipe monitor service load state"
                    f" {load_state or 'unknown'}{detail}; reinstall or unmask the unit"
                )
                healthy = False
            elif (service_info.active_state or "").lower() == "failed":
                logger(
                    "Anti-wipe monitor service failed on its last run; inspect"
                    " journalctl -u anti_wipe_monitor.service"
                )
                healthy = False

            enabled, enable_state = unit_enabled(ANTI_WIPE_SERVICE)
            normalized = enable_state.lower()
            if not enabled and normalized not in UNIT_ALLOWED_ENABLE_STATES:
                logger(
                    "Anti-wipe monitor service not enabled; run"
                    f" 'systemctl enable --now {ANTI_WIPE_SERVICE}'"
                )
                healthy = False

    if healthy:
        logger("Anti-wipe monitoring verified")

    return healthy


def check_resource_monitor(logger: Callable[[str], None]) -> bool:
    """Audit the resource monitor log and supporting timers."""

    log_path = RESOURCE_MONITOR_LOG
    if not log_path.exists():
        logger(
            f"Resource monitor log missing at {log_path}; ensure {RESOURCE_MONITOR_TIMER} has run"
        )
        return False

    if not log_path.is_file():
        logger(f"Resource monitor log {log_path} is not a regular file")
        return False

    healthy = True

    if not _check_secure_path(log_path, "Resource monitor log", logger):
        healthy = False

    try:
        stat_result = log_path.stat()
    except OSError as exc:
        logger(f"Unable to stat resource monitor log {log_path}: {exc}")
        return False

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
        logger(
            "Resource monitor log timestamp"
            f" {mtime.isoformat()} is {_format_duration(skew)} ahead of the system clock; verify time synchronization"
        )
        healthy = False
    else:
        age = now - mtime
        logger(
            f"Resource monitor log updated {_format_duration(age)} ago"
            f" ({log_path})"
        )
        if age > RESOURCE_MONITOR_STALE_THRESHOLD:
            logger(
                "Resource monitor log older than"
                f" {_format_duration(RESOURCE_MONITOR_STALE_THRESHOLD)}; ensure {RESOURCE_MONITOR_TIMER} is active"
            )
            healthy = False

    tail_lines, tail_error = _read_tail_lines(log_path)
    if tail_error is not None:
        logger(f"Unable to read resource monitor log tail: {tail_error}")
        return False

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
        timestamp = _parse_timestamp(parts[0])
        if timestamp is None:
            malformed += 1
            continue
        parsed_entries.append((timestamp, parts[1].strip()))

    if malformed:
        logger(
            f"Resource monitor log tail contains {malformed} malformed entries;"
            " inspect nn_ids_resource_monitor.py logging"
        )
        healthy = False

    if not parsed_entries:
        logger(
            "Resource monitor log tail empty; ensure nn_ids_resource_monitor.service runs via its timer"
        )
        return False

    latest_time, latest_message = parsed_entries[-1]
    skew = latest_time - now
    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
        logger(
            "Latest resource monitor entry"
            f" {latest_time.isoformat()} is {_format_duration(skew)} ahead of the system clock; verify NTP"
        )
        healthy = False
    else:
        age = now - latest_time
        if age > RESOURCE_MONITOR_STALE_THRESHOLD:
            logger(
                "Latest resource monitor entry older than"
                f" {_format_duration(RESOURCE_MONITOR_STALE_THRESHOLD)};"
                f" ensure {RESOURCE_MONITOR_TIMER} is triggering"
            )
            healthy = False

    missing_events = [
        (entry_time, message)
        for entry_time, message in parsed_entries
        if "process not found" in message.lower()
    ]
    if missing_events:
        last_missing_time = missing_events[-1][0]
        logger(
            "Resource monitor recorded"
            f" {len(missing_events)} missing nn_ids.service events;"
            f" most recent {_format_duration(now - last_missing_time)} ago"
        )
        healthy = False

    spike_entries = [
        entry_time
        for entry_time, message in parsed_entries
        if message.lower().startswith("resource spike")
    ]
    if spike_entries:
        recent_spikes = [
            entry_time
            for entry_time in spike_entries
            if now - entry_time <= RESOURCE_MONITOR_SPIKE_WINDOW
        ]
        if recent_spikes:
            logger(
                f"Resource monitor observed {len(recent_spikes)} resource spike"
                f"{'s' if len(recent_spikes) != 1 else ''} in the last"
                f" {_format_duration(RESOURCE_MONITOR_SPIKE_WINDOW)}"
            )
            if len(recent_spikes) >= RESOURCE_MONITOR_SPIKE_ALERT_COUNT:
                logger(
                    "Resource spike frequency exceeds tolerance;"
                    " investigate CPU and memory pressure"
                )
                healthy = False

    if _systemctl_available(logger):
        service_info = query_unit_state(RESOURCE_MONITOR_SERVICE)
        if service_info is None:
            logger(
                "Unable to query resource monitor service; systemctl show returned no data"
            )
            healthy = False
        else:
            load_state = (service_info.load_state or "").lower()
            unit_file_state = (service_info.unit_file_state or "").lower()
            status_text = format_unit_status(service_info)
            if load_state != "loaded":
                healthy = False
                if load_state == "not-found":
                    logger(
                        f"Resource monitor service ({RESOURCE_MONITOR_SERVICE}) missing; deploy the unit file"
                    )
                elif load_state == "masked":
                    logger(
                        f"Resource monitor service ({RESOURCE_MONITOR_SERVICE}) is masked; unmask the unit"
                    )
                else:
                    detail = f" ({service_info.detail})" if service_info and service_info.detail else ""
                    logger(
                        f"Resource monitor service load state {load_state or 'unknown'}{detail}; investigate systemd"
                    )
            elif unit_file_state == "masked":
                healthy = False
                logger(
                    f"Resource monitor service unit file masked; run 'systemctl unmask {RESOURCE_MONITOR_SERVICE}'"
                )
            else:
                active_state = (service_info.active_state or "").lower()
                if active_state == "failed":
                    healthy = False
                    logger(
                        f"Resource monitor service {status_text}; inspect journalctl -u {RESOURCE_MONITOR_SERVICE}"
                    )
                else:
                    logger(
                        f"Resource monitor service {status_text}"
                    )

        timer_info = query_unit_state(
            RESOURCE_MONITOR_TIMER,
            (
                "LastTriggerUSec",
                "NextElapseUSecRealtime",
                "OnCalendar",
                "TimersCalendar",
            ),
        )
        if timer_info is None:
            logger(
                "Unable to query resource monitor timer; systemctl show returned no data"
            )
            healthy = False
        else:
            load_state = (timer_info.load_state or "").lower()
            unit_file_state = (timer_info.unit_file_state or "").lower()
            status_text = format_unit_status(timer_info)
            enabled, enable_state = unit_enabled(RESOURCE_MONITOR_TIMER)
            enable_state = (enable_state or "").lower()
            active_state = (timer_info.active_state or "").lower()
            if load_state != "loaded":
                healthy = False
                if load_state == "not-found":
                    logger(
                        f"Resource monitor timer ({RESOURCE_MONITOR_TIMER}) missing; deploy the unit file"
                    )
                elif load_state == "masked":
                    logger(
                        f"Resource monitor timer ({RESOURCE_MONITOR_TIMER}) is masked; unmask the unit"
                    )
                else:
                    detail = f" ({timer_info.detail})" if timer_info and timer_info.detail else ""
                    logger(
                        f"Resource monitor timer load state {load_state or 'unknown'}{detail}; investigate systemd"
                    )
            elif unit_file_state == "masked":
                healthy = False
                logger(
                    f"Resource monitor timer unit file masked; run 'systemctl unmask {RESOURCE_MONITOR_TIMER}'"
                )
            else:
                schedule_raw = (
                    (timer_info.properties or {}).get("OnCalendar")
                    or (timer_info.properties or {}).get("TimersCalendar")
                    or ""
                )
                schedule_clean = " ".join(schedule_raw.split())
                if schedule_clean and schedule_clean.lower() != "n/a":
                    logger(f"Resource monitor timer schedule: {schedule_clean}")
                else:
                    logger(
                        f"Resource monitor timer missing OnCalendar schedule; inspect the unit definition"
                    )
                    healthy = False

                if active_state in {"active", "activating"}:
                    logger(
                        f"Resource monitor timer {status_text}"
                    )
                    if not enabled and enable_state not in UNIT_ALLOWED_ENABLE_STATES:
                        logger(
                            "Resource monitor timer not enabled; run 'systemctl enable --now"
                            f" {RESOURCE_MONITOR_TIMER}' to persist monitoring"
                        )
                        healthy = False
                else:
                    healthy = False
                    logger(
                        f"Resource monitor timer {status_text}; run 'systemctl enable --now {RESOURCE_MONITOR_TIMER}' to resume monitoring"
                    )

                last_trigger = _parse_systemd_timestamp(
                    (timer_info.properties or {}).get("LastTriggerUSec", "")
                )
                if last_trigger is None:
                    logger(
                        f"Resource monitor timer has not triggered yet; run 'systemctl start {RESOURCE_MONITOR_TIMER}'"
                    )
                    healthy = False
                else:
                    skew = last_trigger - now
                    if skew > RESOURCE_MONITOR_CLOCK_SKEW:
                        logger(
                            "Resource monitor timer last trigger"
                            f" {last_trigger.isoformat()} is {_format_duration(skew)} ahead of the system clock"
                        )
                        healthy = False
                    else:
                        age = now - last_trigger
                        logger(
                            f"Resource monitor timer last triggered {_format_duration(age)} ago"
                        )
                        if age > RESOURCE_MONITOR_STALE_THRESHOLD + RESOURCE_MONITOR_TIMER_GRACE:
                            logger(
                                "Resource monitor timer last trigger"
                                f" {_format_duration(age)} ago exceeds the five-minute cadence"
                            )
                            healthy = False

                next_trigger = _parse_systemd_timestamp(
                    (timer_info.properties or {}).get("NextElapseUSecRealtime", "")
                )
                if next_trigger is None:
                    logger(
                        f"Resource monitor timer next run unknown; verify the unit with 'systemctl cat {RESOURCE_MONITOR_TIMER}'"
                    )
                    healthy = False
                else:
                    delta = next_trigger - now
                    if delta < -RESOURCE_MONITOR_CLOCK_SKEW:
                        logger(
                            f"Resource monitor timer next run {next_trigger.isoformat()} is in the past; restart the timer"
                        )
                        healthy = False
                    else:
                        logger(
                            f"Resource monitor timer next run in {_format_duration(delta)}"
                        )
                        if delta > RESOURCE_MONITOR_TIMER_INTERVAL + RESOURCE_MONITOR_TIMER_GRACE:
                            logger(
                                "Resource monitor timer next run exceeds the five-minute cadence; adjust OnCalendar"
                            )
                            healthy = False

    if healthy:
        logger(
            "Resource monitor log, service, and timer validated"
        )

    return healthy


def check_autoblock_state(logger: Callable[[str], None]) -> bool:
    """Validate the automatic blocking state file when the feature is enabled."""

    snapshot, parse_issue = _load_configuration_snapshot(logger)
    healthy = not parse_issue

    if snapshot is None:
        logger("Unable to evaluate autoblock state; IDS configuration is missing")
        return False

    raw_toggle = snapshot.data.get("NN_IDS_AUTOBLOCK")
    if raw_toggle not in {"0", "1"}:
        logger("Autoblock toggle (NN_IDS_AUTOBLOCK) missing or invalid; expected 0 or 1")
        return False

    enabled = raw_toggle == "1"
    if not enabled:
        logger("Automatic blocking disabled via NN_IDS_AUTOBLOCK; skipping state validation")
        return healthy

    if not AUTOBLOCK_STATE.exists():
        logger(f"Autoblock state missing at {AUTOBLOCK_STATE}")
        return False

    if not AUTOBLOCK_STATE.is_file():
        logger(f"Autoblock state {AUTOBLOCK_STATE} is not a regular file")
        return False

    if not _check_secure_path(AUTOBLOCK_STATE, "Autoblock state", logger):
        healthy = False

    try:
        raw = AUTOBLOCK_STATE.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read autoblock state {AUTOBLOCK_STATE}: {exc}")
        return False

    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        logger(f"Corrupted JSON in {AUTOBLOCK_STATE}")
        return False

    if not isinstance(payload, dict):
        logger(f"Unexpected structure in {AUTOBLOCK_STATE}; expected JSON object")
        return False

    counts_raw = payload.get("counts")
    if counts_raw is None:
        logger(f"Autoblock state {AUTOBLOCK_STATE} missing 'counts' field; rerun nn_ids_autoblock.service")
        return False
    if not isinstance(counts_raw, dict):
        logger(f"Autoblock 'counts' field has unexpected type {type(counts_raw).__name__}")
        return False

    if len(counts_raw) > 4096:
        logger("Autoblock 'counts' map contains more than 4096 entries; trimming may have failed")
        healthy = False

    valid_counts: Dict[str, int] = {}
    invalid_count_ips: List[str] = []
    for key, value in counts_raw.items():
        if not isinstance(key, str):
            logger(f"Autoblock 'counts' map has non-string key {key!r}")
            healthy = False
            continue
        candidate = key.strip()
        if not candidate:
            logger("Autoblock 'counts' map contains empty IP key")
            healthy = False
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            invalid_count_ips.append(candidate)
        if isinstance(value, bool) or not isinstance(value, int):
            logger(
                f"Autoblock count for {candidate!r} has invalid type {type(value).__name__}; expected integer"
            )
            healthy = False
            continue
        if value < 0:
            logger(f"Autoblock count for {candidate!r} is negative")
            healthy = False
            continue
        valid_counts[candidate] = int(value)

    if invalid_count_ips:
        logger(
            "Autoblock 'counts' map contains invalid IP addresses: "
            + ", ".join(sorted({ip for ip in invalid_count_ips}))
        )
        healthy = False

    blocked_raw = payload.get("blocked")
    if blocked_raw is None:
        logger(f"Autoblock state {AUTOBLOCK_STATE} missing 'blocked' field; rerun nn_ids_autoblock.service")
        return False
    if not isinstance(blocked_raw, dict):
        logger(f"Autoblock 'blocked' field has unexpected type {type(blocked_raw).__name__}")
        return False

    now = datetime.now(timezone.utc)
    blocked_entries: List[Tuple[str, datetime]] = []
    stale_blocks: List[str] = []
    future_blocks: List[str] = []

    for key, value in blocked_raw.items():
        if not isinstance(key, str):
            logger(f"Autoblock 'blocked' map has non-string key {key!r}")
            healthy = False
            continue
        candidate = key.strip()
        if not candidate:
            logger("Autoblock 'blocked' map contains empty IP key")
            healthy = False
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            logger(f"Autoblock 'blocked' map contains invalid IP {candidate!r}")
            healthy = False
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            logger(
                f"Autoblock 'blocked' entry for {candidate!r} has invalid timestamp type {type(value).__name__}"
            )
            healthy = False
            continue
        timestamp = datetime.fromtimestamp(float(value), timezone.utc)
        skew = timestamp - now
        if skew > AUTOBLOCK_CLOCK_SKEW:
            future_blocks.append(f"{candidate} ({_format_duration(skew)})")
        else:
            age = now - timestamp
            if age > AUTOBLOCK_BLOCK_DURATION + AUTOBLOCK_BLOCK_GRACE:
                stale_blocks.append(f"{candidate} ({_format_duration(age)})")
        blocked_entries.append((candidate, timestamp))

    if future_blocks:
        logger(
            "Autoblock entries recorded in the future: "
            + ", ".join(sorted(future_blocks))
            + "; verify system clocks"
        )
        healthy = False

    if stale_blocks:
        logger(
            "Autoblock entries persisted beyond expected duration: "
            + ", ".join(sorted(stale_blocks))
            + f"; blocks should clear within {_format_duration(AUTOBLOCK_BLOCK_DURATION)}"
        )
        healthy = False

    missing_counts = [ip for ip, _ in blocked_entries if ip not in valid_counts]
    if missing_counts:
        logger(
            "Autoblock state missing counts for blocked IPs: "
            + ", ".join(sorted({ip for ip in missing_counts}))
        )
        healthy = False

    insufficient_counts = [
        ip
        for ip, _ in blocked_entries
        if valid_counts.get(ip, 0) < AUTOBLOCK_THRESHOLD
    ]
    if insufficient_counts:
        logger(
            "Autoblock state records blocks before reaching threshold "
            f"{AUTOBLOCK_THRESHOLD}: " + ", ".join(sorted({ip for ip in insufficient_counts}))
        )
        healthy = False

    pos_value = payload.get("pos")
    if pos_value is None:
        logger("Autoblock state missing 'pos' offset; log tail tracking may be inconsistent")
        healthy = False
    elif isinstance(pos_value, bool) or not isinstance(pos_value, int):
        logger(
            f"Autoblock 'pos' value has invalid type {type(pos_value).__name__}; expected integer offset"
        )
        healthy = False
    elif pos_value < 0:
        logger("Autoblock 'pos' offset is negative; state file may be corrupted")
        healthy = False

    try:
        stat_result = AUTOBLOCK_STATE.stat()
    except OSError as exc:
        logger(f"Unable to stat autoblock state {AUTOBLOCK_STATE}: {exc}")
        return False

    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    now = datetime.now(timezone.utc)
    skew = mtime - now
    if skew > AUTOBLOCK_CLOCK_SKEW:
        logger(
            f"Autoblock state timestamp {mtime.isoformat()} is {_format_duration(skew)} ahead of system clock; verify NTP"
        )
        healthy = False
    else:
        age = now - mtime
        blocked_count = len(blocked_entries)
        summary = (
            f"Autoblock tracking {len(valid_counts)} addresses ({blocked_count} active blocks);"
            f" updated {_format_duration(age)} ago"
        )
        if blocked_entries:
            newest = max(timestamp for _, timestamp in blocked_entries)
            summary += f"; newest block {_format_duration(now - newest)} ago"
        logger(summary)
    if age > AUTOBLOCK_STALE_THRESHOLD:
        logger(
            f"Autoblock state older than {_format_duration(AUTOBLOCK_STALE_THRESHOLD)};"
            " ensure nn_ids_autoblock.timer is active"
        )
        healthy = False

    return healthy


def _resolve_threat_feed_endpoints(
    snapshot: Optional[ConfigurationSnapshot],
    logger: Callable[[str], None],
) -> Sequence[str]:
    """Return validated threat feed endpoints from configuration or defaults."""

    endpoints: List[str] = []
    raw_value: Optional[str] = None

    if snapshot is not None:
        raw_value = snapshot.data.get(THREAT_FEED_ENDPOINT_KEY)

    if raw_value:
        for entry in raw_value.split(","):
            candidate = entry.strip()
            if not candidate:
                continue
            parsed = urlsplit(candidate)
            if not parsed.scheme or not parsed.netloc:
                logger(
                    "Threat feed endpoint "
                    f"{candidate!r} missing scheme or host; ignoring malformed entry"
                )
                continue
            endpoints.append(candidate)

    if not endpoints:
        endpoints.extend(THREAT_FEED_DEFAULT_ENDPOINTS)

    unique: List[str] = []
    seen: Set[str] = set()
    for endpoint in endpoints:
        if endpoint in seen:
            continue
        unique.append(endpoint)
        seen.add(endpoint)

    return tuple(unique)


def _probe_threat_feed_endpoint(url: str) -> Tuple[bool, str]:
    """Attempt a lightweight HTTP probe against a threat feed endpoint."""

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
            return _probe_threat_feed_endpoint_get(url)
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def _probe_threat_feed_endpoint_get(url: str) -> Tuple[bool, str]:
    """Fallback to a ranged GET when endpoints reject HEAD requests."""

    request = Request(url)
    request.add_header("User-Agent", THREAT_FEED_USER_AGENT)
    request.add_header("Range", "bytes=0-0")

    try:
        with urlopen(request, timeout=THREAT_FEED_PROBE_TIMEOUT) as response:
            status = getattr(response, "status", None) or response.getcode()
            try:
                response.read(1)
            except Exception:  # pragma: no cover - best effort
                pass
            return True, f"HTTP {status}"
    except HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def check_threat_feed(logger: Callable[[str], None]) -> bool:
    """Validate the threat feed blocklist state when the feature is enabled."""

    snapshot, parse_issue = _load_configuration_snapshot(logger)
    healthy = not parse_issue

    if snapshot is None:
        logger(
            "Unable to evaluate threat feed state; IDS configuration is missing"
        )
        return False

    raw_toggle = snapshot.data.get("NN_IDS_THREAT_FEED")
    if raw_toggle not in {"0", "1"}:
        logger(
            "Threat feed toggle (NN_IDS_THREAT_FEED) missing or invalid; expected 0 or 1"
        )
        return False

    enabled = raw_toggle == "1"
    if not enabled:
        logger(
            "Threat feed automation disabled via NN_IDS_THREAT_FEED; skipping blocklist validation"
        )
        return healthy

    if not THREAT_FEED_STATE.exists():
        logger(f"Threat feed state missing at {THREAT_FEED_STATE}")
        return False

    if not THREAT_FEED_STATE.is_file():
        logger(f"Threat feed state {THREAT_FEED_STATE} is not a regular file")
        return False

    if not _check_secure_path(THREAT_FEED_STATE, "Threat feed state", logger):
        healthy = False

    try:
        raw = THREAT_FEED_STATE.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read threat feed state {THREAT_FEED_STATE}: {exc}")
        return False

    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        logger(f"Corrupted JSON in {THREAT_FEED_STATE}")
        return False

    if not isinstance(payload, dict):
        logger(
            f"Unexpected structure in {THREAT_FEED_STATE}; expected JSON object"
        )
        return False

    blocked_raw = payload.get("blocked")
    if blocked_raw is None:
        logger(
            f"Threat feed state {THREAT_FEED_STATE} missing 'blocked' field; rerun blocklist updater"
        )
        return False
    if not isinstance(blocked_raw, list):
        logger(
            f"Threat feed state 'blocked' field has unexpected type {type(blocked_raw).__name__}"
        )
        return False

    valid_addresses: List[str] = []
    invalid_entries: List[str] = []
    for entry in blocked_raw:
        if isinstance(entry, str):
            candidate = entry.strip()
            if not candidate:
                invalid_entries.append(repr(entry))
                continue
        else:
            invalid_entries.append(repr(entry))
            continue

        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            invalid_entries.append(candidate)
        else:
            valid_addresses.append(candidate)

    if invalid_entries:
        logger(
            "Threat feed blocklist contains invalid entries: "
            + ", ".join(sorted({item for item in invalid_entries}))
        )
        healthy = False

    unique_addresses = len(set(valid_addresses))
    duplicate_count = len(valid_addresses) - unique_addresses
    if duplicate_count > 0:
        logger(
            f"Threat feed blocklist includes {duplicate_count} duplicate entries; regenerate the state file"
        )
        healthy = False

    if unique_addresses == 0:
        logger(
            "Threat feed blocklist contains no valid addresses; ensure the updater is reaching the feeds"
        )
        healthy = False

    try:
        stat_result = THREAT_FEED_STATE.stat()
    except OSError as exc:
        logger(f"Unable to stat threat feed state {THREAT_FEED_STATE}: {exc}")
        return False

    now = datetime.now(timezone.utc)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
    skew = mtime - now
    if skew > THREAT_FEED_CLOCK_SKEW:
        logger(
            f"Threat feed state timestamp {mtime.isoformat()} is {_format_duration(skew)} ahead of system clock; verify NTP"
        )
        healthy = False
    else:
        age = now - mtime
        logger(
            f"Threat feed blocklist tracks {unique_addresses} addresses; updated {_format_duration(age)} ago"
        )
        if age > THREAT_FEED_STALE_THRESHOLD:
            logger(
                f"Threat feed blocklist older than {_format_duration(THREAT_FEED_STALE_THRESHOLD)}; run threat_feed_blocklist.service"
            )
            healthy = False

    endpoints = _resolve_threat_feed_endpoints(snapshot, logger)
    reachable = 0
    for endpoint in endpoints:
        success, detail = _probe_threat_feed_endpoint(endpoint)
        if success:
            logger(f"Threat feed endpoint reachable: {endpoint} ({detail})")
            reachable += 1
        else:
            logger(
                "Threat feed endpoint unreachable: "
                f"{endpoint} ({detail}); investigate network access or remote outages"
            )
            healthy = False

    if reachable == 0:
        logger(
            "Unable to reach any configured threat feed endpoints; remote feeds may be offline or blocked"
        )
        healthy = False

    return healthy


def _validate_snapshot_directory(
    snapshot_dir: Path, logger: Callable[[str], None]
) -> bool:
    snapshot_name = snapshot_dir.name
    healthy = True

    if not _check_secure_path(
        snapshot_dir, f"Snapshot directory {snapshot_name}", logger
    ):
        healthy = False

    for filename, hash_name, label in SNAPSHOT_ARTIFACTS:
        artifact_path = snapshot_dir / filename
        hash_path = snapshot_dir / hash_name
        label_lower = label

        if not artifact_path.exists():
            logger(
                f"Snapshot {snapshot_name} missing {label_lower} file ({artifact_path}); rerun snapshot"
            )
            healthy = False
            continue
        if not artifact_path.is_file():
            logger(
                f"Snapshot {snapshot_name} {artifact_path} is not a regular file; recreate the snapshot"
            )
            healthy = False
            continue
        if not _check_secure_path(
            artifact_path, f"Snapshot {snapshot_name} {label_lower}", logger
        ):
            healthy = False

        if not hash_path.exists():
            logger(
                f"Snapshot {snapshot_name} missing {label_lower} hash file ({hash_path}); rerun snapshot"
            )
            healthy = False
            continue
        if not hash_path.is_file():
            logger(
                f"Snapshot {snapshot_name} hash file {hash_path} is not a regular file; recreate the snapshot"
            )
            healthy = False
            continue
        if not _check_secure_path(
            hash_path, f"Snapshot {snapshot_name} {label_lower} hash", logger
        ):
            healthy = False

        digest = _read_snapshot_hash(snapshot_name, hash_path, label_lower, logger)
        if digest is None:
            healthy = False
            continue

        computed = _compute_file_sha256(artifact_path)
        if computed is None:
            logger(
                f"Snapshot {snapshot_name} unable to read {artifact_path} to verify {label_lower} hash"
            )
            healthy = False
            continue

        if computed.lower() != digest:
            logger(
                f"Snapshot {snapshot_name} {label_lower} digest mismatch ({computed.lower()} != {digest}); rerun snapshot"
            )
            healthy = False
            continue

        try:
            size = artifact_path.stat().st_size
        except OSError as exc:
            logger(
                f"Snapshot {snapshot_name} unable to stat {artifact_path} after verification: {exc}"
            )
            healthy = False
            continue

        if size <= 0:
            logger(
                f"Snapshot {snapshot_name} {label_lower} file empty; confirm snapshot captured data"
            )
            healthy = False
        else:
            logger(
                f"Snapshot {snapshot_name} {label_lower} verified ({size} bytes, sha256 {digest})"
            )

        if filename == SNAPSHOT_DATASET_ARCHIVE:
            if not _validate_snapshot_dataset_archive(
                snapshot_name, artifact_path, logger
            ):
                healthy = False

    expected_entries = {name for name, _, _ in SNAPSHOT_ARTIFACTS} | {
        hash_name for _, hash_name, _ in SNAPSHOT_ARTIFACTS
    }
    try:
        entries = list(snapshot_dir.iterdir())
    except OSError as exc:
        logger(
            f"Snapshot {snapshot_name} unable to enumerate contents of {snapshot_dir}: {exc}"
        )
        return False

    for entry in entries:
        if entry.name in expected_entries:
            continue
        logger(
            f"Snapshot {snapshot_name} contains unexpected entry {entry}; review snapshot contents"
        )
        healthy = False

    return healthy


def check_snapshot_integrity(logger: Callable[[str], None]) -> bool:
    """Ensure IDS snapshots exist, are current, and contain verified artifacts."""

    root: Optional[Path] = None
    for candidate in SNAPSHOT_ROOT_CANDIDATES:
        if candidate.exists():
            root = candidate
            break

    if root is None:
        locations = ", ".join(str(path) for path in SNAPSHOT_ROOT_CANDIDATES)
        logger(f"Snapshot root missing; expected one of: {locations}")
        return False

    healthy = True

    if not _check_secure_path(root, "Snapshot root", logger):
        healthy = False

    snapshots: List[Tuple[datetime, Path]] = []
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        logger(f"Unable to enumerate snapshot root {root}: {exc}")
        return False

    for entry in entries:
        try:
            if entry.is_dir():
                timestamp = _parse_snapshot_timestamp(entry.name)
                if timestamp is None:
                    logger(
                        f"Snapshot root contains unexpected directory {entry.name}; use YYYYMMDDHHMMSS naming"
                    )
                    healthy = False
                    continue
                snapshots.append((timestamp, entry))
            else:
                logger(
                    f"Snapshot root contains unexpected file {entry}; restrict root to snapshot directories"
                )
                healthy = False
        except OSError as exc:
            logger(f"Unable to inspect snapshot entry {entry}: {exc}")
            healthy = False

    if not snapshots:
        logger(
            f"No IDS snapshots found under {root}; run nn_ids_snapshot.py or enable nn_ids_snapshot.timer"
        )
        return False

    snapshots.sort(key=lambda item: item[0])
    now = datetime.now(timezone.utc)
    latest_timestamp, latest_dir = snapshots[-1]

    if latest_timestamp > now + SNAPSHOT_CLOCK_SKEW:
        skew = latest_timestamp - now
        logger(
            f"Latest snapshot {latest_dir.name} timestamp {latest_timestamp.isoformat()} is {_format_duration(skew)} ahead of"
            " system clock; verify time synchronization"
        )
        healthy = False

    age = now - latest_timestamp
    if age > SNAPSHOT_STALE_THRESHOLD:
        logger(
            f"Latest snapshot {latest_dir.name} captured {_format_duration(age)} ago; ensure snapshot timer runs regularly"
        )
        healthy = False
    else:
        logger(
            f"Latest snapshot {latest_dir.name} captured {_format_duration(age)} ago"
        )

    if len(snapshots) < 2:
        logger("Only one snapshot available; schedule recurring captures for redundancy")
        healthy = False

    if len(snapshots) > SNAPSHOT_VALIDATION_LIMIT:
        logger(
            f"Validating the most recent {SNAPSHOT_VALIDATION_LIMIT} snapshots out of {len(snapshots)} found"
        )

    for timestamp, path in snapshots[-SNAPSHOT_VALIDATION_LIMIT:]:
        if timestamp > now + SNAPSHOT_CLOCK_SKEW:
            skew = timestamp - now
            logger(
                f"Snapshot {path.name} timestamp {timestamp.isoformat()} is {_format_duration(skew)} ahead of the system clock"
            )
            healthy = False
        if not _validate_snapshot_directory(path, logger):
            healthy = False

    return healthy


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


def check_time_synchronization(logger: Callable[[str], None]) -> bool:
    """Validate that system clocks remain synchronized with an NTP source."""

    healthy = True
    now = datetime.now(timezone.utc)
    data_sources = 0

    services_checked = False
    service_found = False
    service_running = False

    if _systemctl_available(logger):
        services_checked = True
        for unit, description in TIME_SYNC_SERVICES:
            info = query_unit_state(unit)
            if info is None:
                continue
            load_state = (info.load_state or "").lower()
            if load_state == "not-found":
                continue
            service_found = True
            status_text = format_unit_status(info)
            if load_state != "loaded":
                logger(
                    f"{description} ({unit}) load state {load_state or 'unknown'}; reinstall or repair the unit"
                )
                healthy = False
                continue
            active_state = (info.active_state or "").lower()
            if active_state in {"active", "activating", "running"}:
                service_running = True
                logger(f"{description} ({unit}) {status_text}")
            else:
                logger(
                    f"{description} ({unit}) is {status_text}; start or repair the service to maintain clock sync"
                )
                healthy = False

    if services_checked:
        if not service_found:
            logger(
                "No supported NTP service discovered; install systemd-timesyncd, chronyd, or ntpd to manage clock sync"
            )
            healthy = False
        elif not service_running:
            logger("Time synchronization unit detected but inactive; enable it to keep clocks aligned")
            healthy = False

    show_data: Optional[Dict[str, str]] = None
    timesync_data: Optional[Dict[str, str]] = None
    if _timedatectl_available(logger):
        show_data = _timedatectl_show(logger)
        if show_data is not None:
            data_sources += 1
            system_sync = show_data.get("SystemClockSynchronized")
            if system_sync is not None:
                sync_flag = _parse_bool_text(system_sync)
                if sync_flag is False:
                    logger(
                        "System clock not synchronized according to timedatectl; verify network reachability and NTP services"
                    )
                    healthy = False
                elif sync_flag is True:
                    logger("System clock reported as synchronized")
                else:
                    logger(
                        f"Unable to interpret SystemClockSynchronized={system_sync}; update systemd-timesyncd"
                    )
                    healthy = False
            else:
                logger("timedatectl show omitted SystemClockSynchronized; update systemd-timesyncd")
                healthy = False

            ntp_sync = show_data.get("NTPSynchronized") or show_data.get("NTP")
            if ntp_sync is not None:
                ntp_flag = _parse_bool_text(ntp_sync)
                if ntp_flag is False:
                    logger("timedatectl reports NTP unsynchronized; check upstream servers and firewall access")
                    healthy = False
                elif ntp_flag is True:
                    logger("NTP synchronization active according to timedatectl")
                else:
                    logger(f"Unable to interpret NTPSynchronized value {ntp_sync}; upgrade systemd")
                    healthy = False

        timesync_data = _timedatectl_show_timesync(logger)
        if timesync_data:
            data_sources += 1
            server = timesync_data.get("ServerName") or timesync_data.get("SystemNTPServer")
            address = timesync_data.get("ServerAddress") or timesync_data.get("ServerAddress6")
            if server:
                if address:
                    logger(f"Active NTP server {server} ({address})")
                else:
                    logger(f"Active NTP server {server}")
            else:
                logger("timedatectl show-timesync reported no active NTP server; review timesyncd configuration")
                healthy = False

            state = (timesync_data.get("NTPState") or "").lower()
            if state and state not in {"synchronized", "sync", "active"}:
                logger(f"timedatectl reports NTP state {state or 'unknown'}; investigate sync health")
                healthy = False

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
                    logger(
                        f"Last synchronization {last_sync.isoformat()} leads system time by"
                        f" {_format_duration(skew)}; verify system clocks"
                    )
                    healthy = False
                else:
                    age = now - last_sync
                    logger(f"Last synchronization {_format_duration(age)} ago")
                    if age > TIME_SYNC_STALE_THRESHOLD:
                        logger(
                            "Last synchronization older than"
                            f" {_format_duration(TIME_SYNC_STALE_THRESHOLD)}; check NTP reachability"
                        )
                        healthy = False
            else:
                logger("Unable to determine last synchronization time from timedatectl")
                healthy = False

            offset_raw = timesync_data.get("OffsetUSec")
            if offset_raw:
                offset_delta = _parse_microseconds_delta(offset_raw)
                if offset_delta is None:
                    logger(f"timedatectl reported non-numeric OffsetUSec={offset_raw}")
                    healthy = False
                else:
                    offset_ms = abs(offset_delta.total_seconds()) * 1000
                    limit_ms = TIME_SYNC_OFFSET_THRESHOLD.total_seconds() * 1000
                    if offset_ms > limit_ms:
                        logger(
                            f"Clock offset {offset_ms:.1f} ms exceeds {limit_ms:.0f} ms tolerance; adjust NTP peers"
                        )
                        healthy = False
                    else:
                        logger(f"Clock offset {offset_ms:.1f} ms within tolerance")

            poll_raw = timesync_data.get("PollIntervalUSec")
            if poll_raw:
                poll_delta = _parse_microseconds_delta(poll_raw)
                if poll_delta is None:
                    logger(f"PollIntervalUSec not numeric ({poll_raw}); update systemd-timesyncd")
                    healthy = False
                elif poll_delta > TIME_SYNC_UPDATE_MAX:
                    logger(
                        f"NTP poll interval {_format_duration(poll_delta)} exceeds"
                        f" {_format_duration(TIME_SYNC_UPDATE_MAX)}; tighten schedule"
                    )
                    healthy = False

    chrony_required = show_data is None
    chrony_data = _collect_chronyc_tracking(logger, log_errors=chrony_required)
    if chrony_data:
        data_sources += 1
        ref = chrony_data.get("Reference ID") or chrony_data.get("ReferenceID")
        if ref:
            logger(f"Chrony reference {ref}")

        stratum_raw = chrony_data.get("Stratum")
        if stratum_raw:
            token = stratum_raw.split()[0]
            try:
                stratum = int(token)
            except ValueError:
                logger(f"Chrony stratum value unexpected: {stratum_raw}")
                healthy = False
            else:
                if stratum > TIME_SYNC_STRATUM_MAX:
                    logger(
                        f"Chrony stratum {stratum} exceeds maximum {TIME_SYNC_STRATUM_MAX}; choose closer peers"
                    )
                    healthy = False
                else:
                    logger(f"Chrony stratum {stratum}")

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
                logger(f"Unable to parse chronyc reference time '{ref_time_raw}'")
                healthy = False
            else:
                skew = parsed_ref - now
                if skew > TIME_SYNC_CLOCK_SKEW:
                    logger(
                        f"Chrony reference time {parsed_ref.isoformat()} leads system clock by"
                        f" {_format_duration(skew)}; inspect clock discipline"
                    )
                    healthy = False
                else:
                    age = now - parsed_ref
                    logger(f"Chrony reference updated {_format_duration(age)} ago")
                    if age > TIME_SYNC_STALE_THRESHOLD:
                        logger(
                            "Chrony reference older than"
                            f" {_format_duration(TIME_SYNC_STALE_THRESHOLD)}; investigate peer reachability"
                        )
                        healthy = False

        for label in ("System time", "Last offset", "RMS offset"):
            raw_value = chrony_data.get(label)
            if not raw_value:
                continue
            seconds = _parse_first_float(raw_value)
            if seconds is None:
                logger(f"Unable to parse chronyc {label.lower()} '{raw_value}'")
                healthy = False
                continue
            if abs(seconds) > TIME_SYNC_OFFSET_THRESHOLD.total_seconds():
                logger(
                    f"Chrony {label.lower()} {seconds * 1000:.1f} ms exceeds"
                    f" {TIME_SYNC_OFFSET_THRESHOLD.total_seconds() * 1000:.0f} ms tolerance"
                )
                healthy = False
            else:
                logger(
                    f"Chrony {label.lower()} {seconds * 1000:.1f} ms within tolerance"
                )

        update_raw = chrony_data.get("Update interval")
        if update_raw:
            seconds = _parse_first_float(update_raw)
            if seconds is None:
                logger(f"Unable to parse chronyc update interval '{update_raw}'")
                healthy = False
            else:
                delta = timedelta(seconds=seconds)
                if delta > TIME_SYNC_UPDATE_MAX:
                    logger(
                        f"Chrony update interval {_format_duration(delta)} exceeds"
                        f" {_format_duration(TIME_SYNC_UPDATE_MAX)}"
                    )
                    healthy = False

        leap_status = chrony_data.get("Leap status")
        if leap_status and leap_status.strip().lower() != "normal":
            logger(f"Chrony leap status {leap_status}; clock discipline degraded")
            healthy = False

    elif chrony_required:
        healthy = False

    if data_sources == 0:
        logger(
            "Unable to collect time synchronization telemetry; install systemd-timesyncd or chrony for visibility"
        )
        healthy = False

    if healthy:
        logger("Time synchronization healthy and current")

    return healthy


def check_memory_capacity(logger: Callable[[str], None]) -> bool:
    """Ensure physical memory and swap retain sufficient headroom."""

    try:
        contents = MEMINFO_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read {MEMINFO_PATH}: {exc}")
        return False

    meminfo: Dict[str, int] = {}
    healthy = True

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
            logger(f"Unable to parse value for {key.strip()} in {MEMINFO_PATH}: {raw_value}")
            healthy = False
            continue
        unit = parts[1].lower() if len(parts) > 1 else ""
        if unit == "kb":
            value *= 1024
        meminfo[key.strip()] = value

    for threshold in MEMORY_USAGE_THRESHOLDS:
        total = meminfo.get("MemTotal")
        if total is None or total <= 0:
            logger(
                f"{threshold.label} total memory missing or invalid in {MEMINFO_PATH};"
                " cannot evaluate headroom"
            )
            healthy = False
            continue

        available = meminfo.get("MemAvailable")
        if available is None:
            fallback = meminfo.get("MemFree")
            if fallback is None:
                logger(
                    f"{threshold.label} missing MemAvailable metrics in {MEMINFO_PATH};"
                    " unable to estimate free memory"
                )
                healthy = False
                continue
            logger(
                "MemAvailable missing from /proc/meminfo; using MemFree as a conservative"
                " fallback for available memory"
            )
            available = fallback

        available_ratio = available / total
        logger(
            f"{threshold.label} available memory {_format_bytes(available)}"
            f" ({available_ratio * 100:.1f}%) of {_format_bytes(total)} total"
        )

        if available < threshold.min_available_bytes:
            logger(
                f"{threshold.label} below minimum available memory"
                f" {_format_bytes(threshold.min_available_bytes)}"
            )
            healthy = False
        if available_ratio < threshold.min_available_percent:
            logger(
                f"{threshold.label} below minimum available memory percentage"
                f" {threshold.min_available_percent * 100:.0f}%"
            )
            healthy = False

        swap_total = meminfo.get("SwapTotal")
        swap_free = meminfo.get("SwapFree")

        if swap_total is None or swap_free is None:
            logger(
                f"{threshold.label} swap metrics missing from {MEMINFO_PATH}; cannot"
                " confirm swap headroom"
            )
            healthy = False
            continue

        if swap_total <= 0:
            logger(
                f"{threshold.label} reports swap disabled or zero-sized; configure swap"
                " for resilience"
            )
            healthy = False
            continue

        swap_ratio = swap_free / swap_total
        logger(
            f"{threshold.label} swap free {_format_bytes(swap_free)}"
            f" ({swap_ratio * 100:.1f}%) of {_format_bytes(swap_total)} total"
        )

        if swap_free < threshold.min_swap_free_bytes:
            logger(
                f"{threshold.label} below minimum swap free"
                f" {_format_bytes(threshold.min_swap_free_bytes)}"
            )
            healthy = False
        if swap_ratio < threshold.min_swap_percent:
            logger(
                f"{threshold.label} below minimum swap percentage"
                f" {threshold.min_swap_percent * 100:.0f}%"
            )
            healthy = False

    if healthy:
        logger("Memory capacity thresholds satisfied")

    return healthy


def check_cpu_capacity(logger: Callable[[str], None]) -> bool:
    """Ensure CPU load remains within acceptable per-core thresholds."""

    try:
        contents = LOADAVG_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger(f"Unable to read {LOADAVG_PATH}: {exc}")
        return False

    if not contents:
        logger(f"{LOADAVG_PATH} empty; cannot evaluate CPU load")
        return False

    parts = contents.split()
    if len(parts) < 4:
        logger(f"Unexpected format for {LOADAVG_PATH}: {contents!r}")
        return False

    loads: List[float] = []
    healthy = True
    for idx, token in enumerate(parts[:3], start=1):
        try:
            loads.append(float(token))
        except ValueError:
            logger(
                f"Unable to parse {idx}-minute load average '{token}' from {LOADAVG_PATH}"
            )
            return False

    running: Optional[int] = None
    total_tasks: Optional[int] = None
    queue_token = parts[3]
    if "/" in queue_token:
        run_text, total_text = queue_token.split("/", 1)
        try:
            running = int(run_text)
            total_tasks = int(total_text)
        except ValueError:
            logger(
                f"Unable to parse runnable task counts '{queue_token}' from {LOADAVG_PATH}"
            )
            healthy = False
    else:
        logger(
            f"Unexpected runnable task field '{queue_token}' in {LOADAVG_PATH}; expected 'running/total'"
        )
        healthy = False

    cpu_count = os.cpu_count() or 1
    for threshold, load in zip(CPU_LOAD_THRESHOLDS, loads):
        per_cpu = load / max(cpu_count, 1)
        logger(
            f"{threshold.label} load average {load:.2f} "
            f"({per_cpu:.2f} per CPU across {cpu_count} cores)"
        )
        if per_cpu > threshold.max_per_cpu:
            logger(
                f"{threshold.label} load average exceeds per-CPU limit "
                f"{threshold.max_per_cpu:.2f}; investigate CPU contention"
            )
            healthy = False

    if running is not None:
        queue_ratio = running / max(cpu_count, 1)
        logger(
            f"Run queue reports {running} runnable tasks across {cpu_count} CPUs "
            f"({queue_ratio:.2f} per CPU)"
        )
        if queue_ratio > CPU_RUN_QUEUE_MAX_PER_CPU:
            logger(
                f"Run queue ratio {queue_ratio:.2f} exceeds limit "
                f"{CPU_RUN_QUEUE_MAX_PER_CPU:.2f}; CPU saturation suspected"
            )
            healthy = False

    if total_tasks is not None and total_tasks <= 0:
        logger(
            f"Total task count reported as {total_tasks} in {LOADAVG_PATH}; unexpected value"
        )
        healthy = False

    if healthy:
        logger("CPU load within acceptable thresholds")

    return healthy


def check_disk_capacity(logger: Callable[[str], None]) -> bool:
    """Ensure key filesystems maintain healthy free space."""

    healthy = True

    for threshold in DISK_USAGE_THRESHOLDS:
        path: Optional[Path] = None
        for candidate in threshold.candidates:
            if candidate.exists():
                path = candidate
                break

        if path is None:
            locations = ", ".join(str(candidate) for candidate in threshold.candidates)
            logger(
                f"{threshold.label} path missing; expected one of: {locations}"
            )
            healthy = False
            continue

        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            logger(f"Unable to determine disk usage for {path}: {exc}")
            healthy = False
            continue

        total = usage.total
        free = usage.free
        free_ratio = (free / total) if total else 0.0
        total_text = _format_bytes(total)
        free_text = _format_bytes(free)
        logger(
            f"{threshold.label} free space {free_text} ({free_ratio * 100:.1f}%)"
            f" of {total_text} at {path}"
        )

        if free < threshold.min_free_bytes:
            logger(
                f"{threshold.label} below minimum free space"
                f" {_format_bytes(threshold.min_free_bytes)}"
            )
            healthy = False
        if free_ratio < threshold.min_free_percent:
            logger(
                f"{threshold.label} below minimum free percentage"
                f" {threshold.min_free_percent * 100:.0f}%"
            )
            healthy = False

    if healthy:
        logger("Disk capacity thresholds satisfied")

    return healthy


def check_inode_capacity(logger: Callable[[str], None]) -> bool:
    """Ensure filesystems retain free inodes for creating new files."""

    healthy = True

    for threshold in INODE_USAGE_THRESHOLDS:
        path: Optional[Path] = None
        for candidate in threshold.candidates:
            if candidate.exists():
                path = candidate
                break

        if path is None:
            locations = ", ".join(str(candidate) for candidate in threshold.candidates)
            logger(
                f"{threshold.label} path missing; expected one of: {locations}"
            )
            healthy = False
            continue

        try:
            stats = os.statvfs(path)
        except OSError as exc:
            logger(f"Unable to determine inode usage for {path}: {exc}")
            healthy = False
            continue

        total = stats.f_files
        free = stats.f_favail if stats.f_favail > 0 else stats.f_ffree
        if total <= 0:
            logger(
                f"{threshold.label} reports no inode capacity at {path}; investigate filesystem health"
            )
            healthy = False
            continue

        free_ratio = free / total
        logger(
            f"{threshold.label} free inodes {free:,} ({free_ratio * 100:.1f}%)"
            f" of {total:,} at {path}"
        )

        if free < threshold.min_free_inodes:
            logger(
                f"{threshold.label} below minimum free inode count"
                f" {threshold.min_free_inodes:,}"
            )
            healthy = False
        if free_ratio < threshold.min_free_percent:
            logger(
                f"{threshold.label} below minimum free inode percentage"
                f" {threshold.min_free_percent * 100:.0f}%"
            )
            healthy = False

    if healthy:
        logger("Inode capacity thresholds satisfied")

    return healthy


def check_log_rotation(logger: Callable[[str], None]) -> bool:
    """Validate that logrotate is deployed and enforces secure retention."""

    healthy = True
    config_path: Optional[Path] = None
    for candidate in LOGROTATE_CANDIDATES:
        if candidate.exists():
            config_path = candidate
            break

    if config_path is None:
        locations = ", ".join(str(path) for path in LOGROTATE_CANDIDATES[:-1])
        logger(
            "Logrotate configuration missing; expected deployment under "
            f"{locations}"
        )
        return False

    if config_path == LOGROTATE_SAMPLE:
        locations = ", ".join(str(path) for path in LOGROTATE_CANDIDATES[:-1])
        logger(
            f"Logrotate sample found at {config_path}; deploy it to one of: {locations}"
        )
        return False

    if not _check_secure_path(config_path, "Logrotate configuration", logger):
        healthy = False

    try:
        contents = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger(f"Unable to read logrotate configuration {config_path}: {exc}")
        return False

    state_directive = _detect_logrotate_state_path(contents)
    blocks = _parse_logrotate_config(contents)
    if not blocks:
        logger(
            f"Logrotate configuration {config_path} defines no log targets; add IDS logs"
        )
        healthy = False

    tracked_logs: Dict[Path, LogFileSnapshot] = {}
    for log_path in LOGROTATE_TARGETS:
        matched: Optional[LogrotateBlock] = None
        for block in blocks:
            if fnmatch.fnmatch(str(log_path), block.pattern):
                matched = block
                break
        if matched is None:
            logger(
                f"{log_path} missing from {config_path}; log may grow without rotation"
            )
            healthy = False
            continue
        if matched.pattern != str(log_path):
            logger(
                f"{log_path} covered by logrotate pattern {matched.pattern}"
            )
        if not _validate_logrotate_block(log_path, matched.lines, logger):
            healthy = False
        elif not _validate_log_file_metadata(log_path, logger):
            healthy = False

        tracked_logs[log_path] = _snapshot_log_file(log_path)

    state_candidates: List[Path] = []
    if state_directive is not None:
        state_candidates.append(state_directive)
    state_candidates.extend(LOGROTATE_STATE_CANDIDATES)

    if not _evaluate_logrotate_state(config_path, state_candidates, tracked_logs, logger):
        healthy = False

    if not _debug_logrotate_config(config_path, logger):
        healthy = False

    if not _check_logrotate_scheduler(logger):
        healthy = False

    if healthy:
        logger(f"Log rotation configuration validated via {config_path}")

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
        ("Configuration integrity", check_configuration_integrity(logger)),
        ("Autoblock state", check_autoblock_state(logger)),
        ("Process monitor baseline", check_process_monitor_state(logger)),
        ("Port monitor baseline", check_port_monitor_state(logger)),
        ("Network I/O monitor", check_network_io_monitor(logger)),
        ("Internet access monitor", check_internet_access_monitor(logger)),
        ("Alert reporting", check_alert_reporting(logger)),
        ("SSH access controls", check_ssh_access_controls(logger)),
        ("Anti-wipe monitor", check_anti_wipe_monitor(logger)),
        ("Resource monitor", check_resource_monitor(logger)),
        ("Threat feed blocklist", check_threat_feed(logger)),
        ("Snapshot integrity", check_snapshot_integrity(logger)),
        ("Filesystem hygiene", check_filesystem_security(logger)),
        ("Time synchronization", check_time_synchronization(logger)),
        ("CPU capacity", check_cpu_capacity(logger)),
        ("Memory capacity", check_memory_capacity(logger)),
        ("Disk capacity", check_disk_capacity(logger)),
        ("Inode capacity", check_inode_capacity(logger)),
        ("Log rotation", check_log_rotation(logger)),
    ]

    for name, result in check_results:
        logger(f"{name} check {'passed' if result else 'FAILED'}")

    overall = all(result for _, result in check_results)
    logger(f"Health check {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
