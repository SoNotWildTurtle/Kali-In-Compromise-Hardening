#!/usr/bin/env python3
"""Train and monitor GA Tech malicious system call activity."""
from __future__ import annotations

import argparse
import csv
import os
import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:  # pragma: no cover - optional dependencies may be unavailable in minimal envs
    import joblib
    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
except Exception:  # pragma: no cover - degrade gracefully if scientific stack missing
    joblib = None
    MLPClassifier = None

try:  # pragma: no cover - psutil may not be installed on build hosts
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


DATA_URL = "https://giantpanda.gtisc.gatech.edu/malrec/dataset/syscall_sequences.txt"
DATA_FILE = Path("/opt/nnids/ga_sys_dataset.txt")
MODEL_FILE = Path("/opt/nnids/ga_sys_model.pkl")
TRAIN_LOG = Path("/var/log/ga_tech_sys_train.log")
ALERT_LOG = Path("/var/log/ga_tech_sys_alerts.log")
DETECTIONS_CSV = Path("/opt/nnids/ga_sys_detections.csv")
PROCESS_LOG = Path("/opt/nnids/process_log.csv")

AUDIT_LOG = Path("/var/log/audit/audit.log")

SYSCALL_FEATURES: Sequence[str] = (
    "execve",
    "execveat",
    "ptrace",
    "mprotect",
    "mmap",
    "chmod",
    "chown",
    "setuid",
    "setgid",
    "kill",
    "clone",
    "fork",
    "vfork",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "write",
    "unlink",
    "open",
    "openat",
    "mount",
    "umount2",
)

ESCALATION_SYSCALLS = {
    "setuid",
    "setgid",
    "chmod",
    "chown",
    "mount",
    "umount2",
}

NETWORK_SYSCALLS = {
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
}

SUSPICIOUS_SYSCALLS = {
    "ptrace",
    "mprotect",
    "kill",
    "clone",
    "fork",
    "vfork",
    "execve",
    "execveat",
    "unlink",
    *ESCALATION_SYSCALLS,
}

FEATURE_COLUMNS: Sequence[str] = tuple(
    [f"freq_{name}" for name in SYSCALL_FEATURES]
    + [
        "total_norm",
        "suspicious_ratio",
        "unique_ratio",
        "max_ratio",
        "privilege_flag",
        "network_flag",
    ]
)

SYSCALL_NUMBER_MAP = {
    "0": "read",
    "1": "write",
    "2": "open",
    "3": "close",
    "41": "socket",
    "42": "connect",
    "43": "accept",
    "44": "sendto",
    "45": "recvfrom",
    "49": "bind",
    "50": "listen",
    "56": "clone",
    "57": "fork",
    "58": "vfork",
    "59": "execve",
    "60": "exit",
    "61": "wait4",
    "62": "kill",
    "87": "unlink",
    "90": "chmod",
    "92": "chown",
    "105": "setuid",
    "106": "setgid",
    "158": "arch_prctl",
    "165": "mount",
    "166": "umount2",
    "217": "getdents64",
    "257": "openat",
    "262": "newfstatat",
    "322": "execveat",
    "329": "preadv2",
}

AUDIT_SYSCALL_RE = re.compile(
    r"type=SYSCALL[^\n]* pid=(?P<pid>\d+)[^\n]* comm=\"?(?P<comm>[^\"\s]+)\"?[^\n]* syscall=(?P<syscall>[\w-]+)"
)


def download_dataset() -> None:
    """Retrieve the GA Tech malicious system call dataset if missing."""

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        return
    try:
        urllib = __import__("urllib.request", fromlist=["urlretrieve"])  # lazy import
        urllib.request.urlretrieve(DATA_URL, DATA_FILE)
    except Exception:
        # Operate with synthetic samples if the dataset cannot be fetched
        pass


def normalize_syscall(token: str) -> str:
    """Reduce a syscall token to a canonical lowercase name."""

    token = token.strip().strip('"').lower()
    if not token:
        return token
    if token.startswith("syscall="):
        token = token.split("=", 1)[1]
    if token.startswith("sys_"):
        token = token[4:]
    token = token.strip("[](),")
    if token.isdigit():
        return SYSCALL_NUMBER_MAP.get(token, token)
    if token.endswith("64") and token[:-2].isdigit():
        return SYSCALL_NUMBER_MAP.get(token[:-2], token)
    return token


def build_feature_vector(
    calls: Sequence[str],
    features: Sequence[str] = SYSCALL_FEATURES,
) -> List[float]:
    """Convert a syscall sequence into the ML feature vector."""

    total = len(calls)
    denom = float(total) if total else 1.0
    counts = Counter(calls)
    vector = [counts.get(name, 0) / denom for name in features]
    suspicious_count = sum(counts.get(name, 0) for name in SUSPICIOUS_SYSCALLS)
    unique_ratio = len(set(calls)) / denom
    max_ratio = max((count / denom for count in counts.values()), default=0.0)
    vector.extend(
        [
            min(total / 100.0, 1.0),
            suspicious_count / denom,
            unique_ratio,
            max_ratio,
            1.0 if any(name in ESCALATION_SYSCALLS for name in counts) else 0.0,
            1.0 if any(name in NETWORK_SYSCALLS for name in counts) else 0.0,
        ]
    )
    return vector


def fallback_samples() -> List[Tuple[List[str], int]]:
    """Generate synthetic samples when the GA Tech dataset is unavailable."""

    malicious_patterns = [
        ["execve", "ptrace", "mprotect", "write", "write", "setuid", "unlink"],
        ["execve", "connect", "connect", "sendto", "sendto", "kill"],
        ["execve", "chmod", "chown", "setgid", "setuid", "execve"],
        ["clone", "execve", "ptrace", "mprotect", "write", "unlink"],
        ["execve", "socket", "connect", "execve", "mount", "umount2"],
        ["execve", "mprotect", "mprotect", "ptrace", "ptrace", "kill"],
    ]
    benign_patterns = [
        ["open", "read", "write", "close", "fstat", "munmap"],
        ["openat", "read", "read", "write", "close"],
        ["open", "getdents64", "close", "exit"],
        ["open", "read", "write", "fsync", "close"],
        ["open", "stat", "open", "read", "close"],
        ["openat", "read", "write", "lseek", "close"],
    ]
    samples: List[Tuple[List[str], int]] = []
    for pattern in malicious_patterns:
        expanded = pattern + pattern[-3:]
        samples.append((expanded, 1))
    for pattern in benign_patterns:
        expanded = pattern + pattern[::-1][:2]
        samples.append((expanded, 0))
    return samples


def load_dataset() -> Tuple[List[List[float]], List[int]]:
    """Parse the GA Tech dataset (or synthetic fallback) into feature vectors."""

    samples: List[Tuple[List[str], int]] = []
    if DATA_FILE.exists():
        try:
            with DATA_FILE.open() as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    parts = re.split(r"[,;\s]+", line)
                    if not parts:
                        continue
                    label_token = parts[0].lower()
                    if label_token in {"malicious", "bad", "1"}:
                        label = 1
                        tokens = parts[1:]
                    elif label_token in {"benign", "good", "0"}:
                        label = 0
                        tokens = parts[1:]
                    else:
                        # try the last column as label
                        tail = parts[-1].lower()
                        if tail in {"malicious", "bad", "1"}:
                            label = 1
                            tokens = parts[:-1]
                        elif tail in {"benign", "good", "0"}:
                            label = 0
                            tokens = parts[:-1]
                        else:
                            # look for audit log style tokens
                            tokens = [tok for tok in parts if "syscall=" in tok]
                            if not tokens:
                                continue
                            label = 1
                    calls = [normalize_syscall(tok) for tok in tokens if tok]
                    calls = [call for call in calls if call]
                    if calls:
                        samples.append((calls, label))
        except Exception:
            samples = []
    if not samples:
        samples = fallback_samples()
    X = [build_feature_vector(calls) for calls, _ in samples]
    y = [label for _, label in samples]
    return X, y


def train_model(verbose: bool = False) -> None:
    """Train the system call classifier and persist the resulting bundle."""

    if MLPClassifier is None or joblib is None:
        raise RuntimeError("scikit-learn and joblib are required for training")

    X, y = load_dataset()
    if len(set(y)) < 2:
        raise RuntimeError("Dataset does not contain both benign and malicious samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    clf = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=40)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    probas = clf.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, zero_division=0)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    roc = roc_auc_score(y_test, probas)
    cm = confusion_matrix(y_test, preds).tolist()

    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": clf,
            "features": list(FEATURE_COLUMNS),
            "syscall_features": list(SYSCALL_FEATURES),
        },
        MODEL_FILE,
    )
    TRAIN_LOG.parent.mkdir(parents=True, exist_ok=True)
    with TRAIN_LOG.open("a") as handle:
        handle.write(
            f"{datetime.utcnow().isoformat()} accuracy={acc:.3f} f1={f1:.3f} "
            f"precision={prec:.3f} recall={rec:.3f} roc_auc={roc:.3f} cm={cm}\n"
        )
    if verbose:
        print(
            "Training complete: "
            f"accuracy={acc:.3f} f1={f1:.3f} precision={prec:.3f} "
            f"recall={rec:.3f} roc_auc={roc:.3f}"
        )


def load_model_bundle() -> Optional[Dict[str, object]]:
    """Load the persisted model bundle, returning None if unavailable."""

    if joblib is None or not MODEL_FILE.exists():
        return None
    try:
        bundle = joblib.load(MODEL_FILE)
        if "model" in bundle:
            return bundle
    except Exception:
        return None
    return None


def describe_detection(counts: Counter[str]) -> str:
    """Create a human readable explanation for a suspicious syscall mix."""

    reasons: List[str] = []
    if any(name in ESCALATION_SYSCALLS for name in counts):
        reasons.append("privilege escalation attempt")
    if any(name in NETWORK_SYSCALLS for name in counts):
        reasons.append("unexpected network beaconing")
    if counts.get("ptrace"):
        reasons.append("ptrace usage detected")
    if counts.get("mprotect"):
        reasons.append("memory permission changes")
    if counts.get("execve", 0) > 1 or counts.get("execveat"):
        reasons.append("multiple process launches")
    if not reasons:
        reasons.append("anomalous syscall distribution")
    return "; ".join(reasons)


def record_detection(
    pid: int,
    command: str,
    probability: float,
    counts: Counter[str],
    reason: str,
) -> None:
    """Persist detection details to CSV logs and the shared process log."""

    timestamp = datetime.utcnow().isoformat()
    DETECTIONS_CSV.parent.mkdir(parents=True, exist_ok=True)
    top_counts = ";".join(
        f"{name}={counts[name]}" for name, _ in counts.most_common(5)
    )
    with DETECTIONS_CSV.open("a", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([timestamp, str(pid), command, f"{probability:.4f}", reason, top_counts])
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open("a") as handle:
        top_three = ", ".join(f"{name}x{counts[name]}" for name, _ in counts.most_common(3))
        handle.write(
            f"{timestamp} PID {pid} {command} prob={probability:.2f} reason={reason} top=[{top_three}]\n"
        )
    PROCESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PROCESS_LOG.open("a", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [timestamp, command, pid, f"ga_syscall: {reason} (p={probability:.2f})"]
        )


def prune_history(
    history: Dict[int, Deque[Tuple[str, float]]],
    ttl: float,
) -> None:
    """Drop stale entries to control memory usage."""

    now = time.time()
    stale = [pid for pid, calls in history.items() if calls and now - calls[-1][1] > ttl]
    for pid in stale:
        del history[pid]


def stream_audit_log(interval: float) -> Iterator[Tuple[int, str, str, float]]:
    """Yield syscall events from the audit log if available."""

    if not AUDIT_LOG.exists():
        return
    try:
        with AUDIT_LOG.open() as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(interval)
                    try:
                        current_size = AUDIT_LOG.stat().st_size
                    except Exception:
                        current_size = position
                    if current_size < position:
                        handle.seek(0)
                    continue
                position = handle.tell()
                match = AUDIT_SYSCALL_RE.search(line)
                if not match:
                    continue
                pid = int(match.group("pid"))
                comm = match.group("comm")
                syscall = normalize_syscall(match.group("syscall"))
                if syscall:
                    yield pid, comm, syscall, time.time()
    except FileNotFoundError:
        return


def stream_proc(interval: float) -> Iterator[Tuple[int, str, str, float]]:
    """Fallback syscall stream by sampling /proc when audit logs are unavailable."""

    last_syscalls: Dict[int, str] = {}
    while True:
        pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
        for pid_str in pids:
            pid = int(pid_str)
            syscall_path = Path(f"/proc/{pid}/syscall")
            try:
                content = syscall_path.read_text().strip().split()
            except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                continue
            if not content:
                continue
            syscall = normalize_syscall(content[0])
            if not syscall:
                continue
            if last_syscalls.get(pid) == syscall:
                continue
            last_syscalls[pid] = syscall
            name = pid_str
            if psutil is not None:
                try:
                    name = psutil.Process(pid).name() or name
                except Exception:
                    name = pid_str
            yield pid, name, syscall, time.time()
        time.sleep(interval)


def event_stream(interval: float) -> Iterator[Tuple[int, str, str, float]]:
    """Return the most appropriate syscall event iterator for the environment."""

    audit_iter = stream_audit_log(interval)
    if audit_iter is not None:
        produced = False
        for event in audit_iter:
            produced = True
            yield event
        if produced:
            return
    yield from stream_proc(interval)


def monitor_syscalls(
    duration: int = 0,
    interval: float = 1.0,
    window: int = 25,
    threshold: Optional[float] = None,
    continuous: bool = False,
    verbose: bool = False,
) -> int:
    """Monitor live syscalls and return the number of alerts generated."""

    bundle = load_model_bundle()
    if bundle is None:
        if verbose:
            print("GA Tech system call model not available; skipping monitoring")
        return 0
    clf = bundle["model"]
    feature_names = bundle.get("syscall_features", list(SYSCALL_FEATURES))
    if threshold is None:
        threshold = float(os.getenv("NN_SYS_THRESHOLD", os.getenv("NN_IDS_THRESHOLD", "0.6")))
    window = max(window, 10)
    cooldown = float(os.getenv("NN_SYS_COOLDOWN", "60"))
    ttl = float(os.getenv("NN_SYS_WINDOW_TTL", "180"))

    history: Dict[int, Deque[Tuple[str, float]]] = defaultdict(
        lambda: deque(maxlen=window * 4)
    )
    last_alert: Dict[int, float] = {}
    alerts = 0
    end_time = time.time() + duration if duration > 0 else None

    stream = event_stream(interval)
    while True:
        try:
            pid, command, syscall, timestamp = next(stream)
        except StopIteration:
            break
        except Exception:
            time.sleep(interval)
            continue
        history[pid].append((syscall, timestamp))
        prune_history(history, ttl)
        calls = [name for name, _ in list(history[pid])[-window:]]
        if len(calls) < window:
            if end_time and time.time() >= end_time and not continuous:
                break
            continue
        vector = build_feature_vector(calls, feature_names)
        try:
            prob = float(clf.predict_proba([vector])[0][1])
        except Exception:
            prob = float(clf.predict([vector])[0])
        if prob >= threshold:
            last = last_alert.get(pid, 0.0)
            if timestamp - last >= cooldown:
                counts = Counter(calls)
                reason = describe_detection(counts)
                record_detection(pid, command, prob, counts, reason)
                alerts += 1
                last_alert[pid] = timestamp
                if verbose:
                    top_calls = ", ".join(
                        f"{name}x{counts[name]}" for name, _ in counts.most_common(3)
                    )
                    print(
                        f"Alert: PID {pid} {command} prob={prob:.2f} reason={reason} top=[{top_calls}]"
                    )
        if end_time and time.time() >= end_time:
            if continuous:
                break
            if not continuous:
                break
    return alerts


def summarize_detections(top_n: int = 5) -> str:
    """Return a textual summary of logged GA Tech system call detections."""

    if not DETECTIONS_CSV.exists():
        return "No GA Tech system call detections recorded yet."
    processes: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    syscall_counts: Counter[str] = Counter()
    total = 0
    with DETECTIONS_CSV.open() as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 6:
                continue
            _, pid, command, probability, reason, top_counts = row
            label = f"{command} (PID {pid})"
            processes[label] += 1
            reasons[reason] += 1
            for item in top_counts.split(";"):
                if not item:
                    continue
                name, _, count = item.partition("=")
                try:
                    syscall_counts[name] += int(count)
                except ValueError:
                    continue
            total += 1
    if total == 0:
        return "No GA Tech system call detections recorded yet."
    lines = [
        f"Total GA Tech system call detections: {total}",
        "Top processes:",
    ]
    for proc, count in processes.most_common(max(1, top_n)):
        lines.append(f"  - {proc}: {count}")
    lines.append("Top reasons:")
    for reason, count in reasons.most_common(max(1, top_n)):
        lines.append(f"  - {reason}: {count}")
    lines.append("Most frequent suspicious syscalls:")
    for name, count in syscall_counts.most_common(max(1, top_n)):
        lines.append(f"  - {name}: {count}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GA Tech system call anomaly detector"
    )
    parser.add_argument("--train", action="store_true", help="train the GA Tech system call model")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="run a short-lived syscall monitor using the trained model",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="continuously monitor system calls until interrupted",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=int(os.getenv("GA_SYS_DURATION", "120")),
        help="duration in seconds for scans/monitoring (0 = infinite)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("GA_SYS_INTERVAL", "1.0")),
        help="sampling interval in seconds",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=int(os.getenv("GA_SYS_WINDOW", "25")),
        help="number of syscalls per process to evaluate",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.getenv("GA_SYS_THRESHOLD", os.getenv("NN_SYS_THRESHOLD", "0.6"))),
        help="probability threshold for flagging activity",
    )
    parser.add_argument(
        "--summarize",
        action="store_true",
        help="print a summary of logged detections",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="emit progress information to stdout",
    )
    args = parser.parse_args()

    default_action = not any(
        [args.train, args.scan, args.monitor, args.summarize]
    )
    if args.train or default_action:
        download_dataset()
        try:
            train_model(verbose=args.verbose)
        except Exception as exc:
            if args.verbose:
                print(f"Training failed: {exc}")
    run_monitor = args.scan or args.monitor
    if run_monitor:
        duration = max(0, args.duration)
        if args.monitor and duration == 0:
            duration = 0
        alerts = monitor_syscalls(
            duration=duration,
            interval=max(0.1, args.interval),
            window=max(10, args.window),
            threshold=args.threshold,
            continuous=args.monitor,
            verbose=args.verbose,
        )
        if args.verbose:
            print(f"Monitoring finished with {alerts} alert(s).")
    if args.summarize:
        print(summarize_detections())


if __name__ == "__main__":
    main()
