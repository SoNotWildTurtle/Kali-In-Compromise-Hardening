#!/usr/bin/env python3
"""Train and run a GA Tech based malicious process detector.

This helper downloads the Georgia Tech malicious process dataset, augments it
with any locally flagged samples, trains a tiny neural network, and scans the
currently running processes. Training metrics are appended to
``/var/log/ga_tech_proc_train.log`` and any newly flagged process hashes are
stored in ``/opt/nnids/ga_proc_local.txt`` so future runs can evolve the model.
Flagged processes are enriched with runtime context, scored with an additional
heuristic risk model that factors in baseline hashes, file integrity, and
runtime behaviour, and then stored in ``/opt/nnids/ga_proc_detections.csv``.
Alerts are also appended to the shared ``/opt/nnids/process_log.csv`` dataset
and emitted to ``/var/log/ga_tech_proc_alerts.log``. A ``--monitor`` mode can
continuously rescan processes, ``--refresh-baseline`` rebuilds a benign hash
inventory, and ``--summarize`` prints a quick detection digest so operators can
understand why items were flagged.
"""

import argparse
import csv
import hashlib
import os
import stat
import time
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Set, Tuple

import psutil

try:  # pragma: no cover - dependencies may be missing in minimal envs
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    import numpy as np
    import joblib
except Exception:  # pragma: no cover - libraries may not be installed in build env
    MLPClassifier = None


DATA_URL = "https://giantpanda.gtisc.gatech.edu/malrec/dataset/uuid_md5.txt"
DATA_FILE = Path("/opt/nnids/ga_proc_dataset.txt")
LOCAL_MALICIOUS = Path("/opt/nnids/ga_proc_local.txt")
BASELINE_FILE = Path("/opt/nnids/ga_proc_baseline.txt")
MODEL_FILE = Path("/opt/nnids/ga_proc_model.pkl")
ALERT_LOG = Path("/var/log/ga_tech_proc_alerts.log")
TRAIN_LOG = Path("/var/log/ga_tech_proc_train.log")
PROCESS_LOG = Path("/opt/nnids/process_log.csv")
DETECTIONS_CSV = Path("/opt/nnids/ga_proc_detections.csv")
SUMMARY_HEADER = "GA Tech process detections summary:"

PSUTIL_EXCEPTIONS = (psutil.NoSuchProcess, psutil.AccessDenied)
if hasattr(psutil, "ZombieProcess"):
    PSUTIL_EXCEPTIONS = PSUTIL_EXCEPTIONS + (psutil.ZombieProcess,)  # type: ignore[arg-type]


def download_dataset() -> None:
    """Fetch the GA Tech malicious process dataset if missing."""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        return
    try:
        urllib.request.urlretrieve(DATA_URL, DATA_FILE)
    except Exception:
        pass


def _load_malicious_hashes():
    """Return md5 hashes from the GA dataset and locally flagged samples."""
    hashes = []
    if DATA_FILE.exists():
        with DATA_FILE.open() as f:
            for line in f:
                parts = line.strip().split()
                if parts:
                    hashes.append(parts[-1])
    if LOCAL_MALICIOUS.exists():
        with LOCAL_MALICIOUS.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    hashes.append(line)
    return hashes


def _append_local_hash(md5: str) -> None:
    """Store md5 in the local malicious hash file if new."""
    LOCAL_MALICIOUS.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if LOCAL_MALICIOUS.exists():
        with LOCAL_MALICIOUS.open() as f:
            existing = {line.strip() for line in f if line.strip()}
    if md5 not in existing:
        with LOCAL_MALICIOUS.open("a") as f:
            f.write(md5 + "\n")


def _gather_context(proc: psutil.Process) -> dict:
    """Collect contextual details for richer alerting."""
    context = {
        "cmdline": "",
        "username": "",
        "start_time": "",
        "connections": 0,
    }
    try:
        cmdline = proc.cmdline()
        if cmdline:
            context["cmdline"] = " ".join(cmdline)
    except PSUTIL_EXCEPTIONS:
        pass
    try:
        context["username"] = proc.username()
    except PSUTIL_EXCEPTIONS:
        pass
    try:
        created = proc.create_time()
        if created:
            context["start_time"] = datetime.utcfromtimestamp(created).isoformat()
    except PSUTIL_EXCEPTIONS:
        pass
    try:
        conns = proc.connections(kind="inet")
        context["connections"] = sum(1 for conn in conns if getattr(conn, "status", None))
    except PSUTIL_EXCEPTIONS:
        pass
    except Exception:
        # ``connections`` can raise ValueError if the process disappears mid-call
        pass
    return context


def _load_baseline_hashes() -> Set[str]:
    """Return the set of baseline process hashes marked as benign."""

    if not BASELINE_FILE.exists():
        return set()
    with BASELINE_FILE.open() as handle:
        return {line.strip() for line in handle if line.strip()}


def _write_baseline(entries: Iterable[str]) -> int:
    """Persist the provided hashes as the benign baseline."""

    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted({entry for entry in entries if entry})
    with BASELINE_FILE.open("w") as handle:
        handle.write("\n".join(unique) + ("\n" if unique else ""))
    return len(unique)


def refresh_baseline(verbose: bool = False) -> int:
    """Generate a new baseline from currently running processes."""

    hashes: Set[str] = set()
    skipped = 0
    for proc in psutil.process_iter(["exe"]):
        exe = proc.info.get("exe")
        if not exe or not os.path.exists(exe):
            skipped += 1
            continue
        try:
            with open(exe, "rb") as fh:
                hashes.add(hashlib.md5(fh.read()).hexdigest())
        except PSUTIL_EXCEPTIONS:
            skipped += 1
        except Exception:
            skipped += 1
    count = _write_baseline(hashes)
    if verbose:
        print(
            f"Captured {count} unique executable hash(es) for the baseline "
            f"(skipped {skipped} process(es)). Baseline saved to {BASELINE_FILE}."
        )
    elif not hashes:
        print("No processes were accessible while refreshing the baseline.")
    else:
        print(f"Baseline updated with {count} executable hash(es).")
    return count


def _log_process_event(name: str, pid: int, reason: str) -> None:
    """Append a row to the shared process log."""
    PROCESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PROCESS_LOG.open("a", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([datetime.utcnow().isoformat(), name, pid, reason])


def _heuristic_analysis(
    proc: psutil.Process,
    exe: str,
    md5: str,
    context: Dict[str, object],
    baseline_hashes: Set[str],
) -> Tuple[float, Sequence[str]]:
    """Score additional heuristics to augment the neural model."""

    reasons = []
    score = 0.0
    path = Path(exe)

    if md5 not in baseline_hashes:
        reasons.append("hash not present in benign baseline")
        score += 0.35

    if exe.startswith(("/tmp", "/var/tmp")):
        reasons.append("executing from a temporary directory")
        score += 0.25

    if context.get("connections", 0) and int(context.get("connections", 0)) >= 3:
        reasons.append(f"maintaining {context['connections']} network connection(s)")
        score += 0.15

    try:
        stat_result = path.stat()
        if stat_result.st_mode & stat.S_IWOTH:
            reasons.append("executable is world-writable")
            score += 0.2
        if context.get("username") == "root" and stat_result.st_uid != 0:
            reasons.append("root executing non-root owned binary")
            score += 0.15
        if time.time() - stat_result.st_mtime < 3600:
            reasons.append("binary modified within the last hour")
            score += 0.1
    except Exception:
        pass

    try:
        parent = proc.parent()
        if parent and parent.pid not in (0, 1):
            parent_name = parent.name()
            if parent_name and parent_name.lower() in {"sh", "bash", "dash"}:
                reasons.append(f"spawned from interactive shell ({parent_name})")
                score += 0.1
    except PSUTIL_EXCEPTIONS:
        pass
    except Exception:
        pass

    return min(1.0, score), reasons


def _record_detection(
    proc: psutil.Process,
    exe: str,
    md5: str,
    proba: float,
    threshold: float,
    risk: float,
    risk_threshold: float,
    heuristic_reasons: Sequence[str],
    verbose: bool,
    context: Optional[Dict[str, object]] = None,
) -> None:
    """Persist detection details across the various logs."""

    context = context or _gather_context(proc)
    reasons = []
    if proba >= threshold:
        reasons.append(f"score {proba:.2f} >= threshold {threshold:.2f}")
    else:
        reasons.append(f"score {proba:.2f} < threshold {threshold:.2f}")
    reasons.extend(heuristic_reasons)
    reasons.append(f"combined risk {risk:.2f} (minimum {risk_threshold:.2f})")
    reason_text = "; ".join(reasons)
    timestamp = datetime.utcnow().isoformat()

    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open("a") as log:
        log.write(
            f"{timestamp} {proc.info.get('name', 'unknown')} PID {proc.info.get('pid')} "
            f"score {proba:.2f} path {exe or 'unknown'} user {context.get('username') or 'unknown'} "
            f"reason(s): {reason_text} cmdline={context.get('cmdline', '')}\n"
        )

    DETECTIONS_CSV.parent.mkdir(parents=True, exist_ok=True)
    new_file = not DETECTIONS_CSV.exists()
    with DETECTIONS_CSV.open("a", newline="") as csv_handle:
        writer = csv.writer(csv_handle)
        if new_file:
            writer.writerow(
                [
                    "timestamp",
                    "process",
                    "pid",
                    "path",
                    "md5",
                    "probability",
                    "username",
                    "cmdline",
                    "started",
                    "connections",
                    "reasons",
                ]
            )
        writer.writerow(
            [
                timestamp,
                proc.info.get("name", ""),
                proc.info.get("pid", 0),
                exe,
                md5,
                f"{proba:.4f}",
                context.get("username", ""),
                context.get("cmdline", ""),
                context.get("start_time", ""),
                context.get("connections", 0),
                reason_text,
            ]
        )

    _log_process_event(proc.info.get("name", ""), proc.info.get("pid", 0), f"ga_tech_model: {reason_text}")

    if verbose:
        print(
            f"[{timestamp}] Flagged {proc.info.get('name', 'unknown')} (PID {proc.info.get('pid')}) "
            f"risk={risk:.2f} probability={proba:.2f}"
        )


def train_model() -> None:
    """Train a small neural network and log evaluation metrics."""
    if MLPClassifier is None:
        return
    hashes = _load_malicious_hashes()
    malicious = [[int(c, 16) for c in h[:32]] for h in hashes]
    benign = []
    for proc in psutil.process_iter(["exe"]):
        exe = proc.info.get("exe")
        if not exe or not os.path.exists(exe):
            continue
        try:
            with open(exe, "rb") as fh:
                md5 = hashlib.md5(fh.read()).hexdigest()
            benign.append([int(c, 16) for c in md5[:32]])
        except Exception:
            continue
        if len(benign) >= len(malicious):
            break
    if not malicious or not benign:
        return
    X = np.array(malicious + benign)
    y = np.array([1] * len(malicious) + [0] * len(benign))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = MLPClassifier(hidden_layer_sizes=(32,), max_iter=200)
    clf.fit(X_train, y_train)
    probs = clf.predict_proba(X_test)[:, 1]
    preds = (probs >= 0.5).astype(int)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    roc = roc_auc_score(y_test, probs)
    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    TRAIN_LOG.parent.mkdir(parents=True, exist_ok=True)
    with TRAIN_LOG.open("a") as log:
        log.write(
            f"{datetime.utcnow().isoformat()} accuracy={acc:.3f} f1={f1:.3f} precision={prec:.3f} recall={rec:.3f} roc_auc={roc:.3f} tn={tn} fp={fp} fn={fn} tp={tp} samples={len(y)}\n"
        )
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_FILE)


def run_scan(
    threshold: float,
    risk_threshold: float,
    seen: Optional[Set[str]] = None,
    verbose: bool = False,
    baseline_hashes: Optional[Set[str]] = None,
) -> Tuple[Set[str], int]:
    """Scan running processes and log any flagged by the model."""

    if MLPClassifier is None or not MODEL_FILE.exists():
        return set(), 0
    clf = joblib.load(MODEL_FILE)
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    seen = seen or set()
    current_seen: Set[str] = set()
    new_hits = 0
    baseline_hashes = baseline_hashes if baseline_hashes is not None else _load_baseline_hashes()
    for proc in psutil.process_iter(["pid", "exe", "name"]):
        exe = proc.info.get("exe")
        if not exe or not os.path.exists(exe):
            continue
        try:
            with open(exe, "rb") as fh:
                md5 = hashlib.md5(fh.read()).hexdigest()
            feats = [int(c, 16) for c in md5[:32]]
            proba = clf.predict_proba([feats])[0][1]
            context = _gather_context(proc)
            heuristic_score, heuristic_reasons = _heuristic_analysis(
                proc, exe, md5, context, baseline_hashes
            )
            combined_risk = max(proba, heuristic_score)
            if proba >= threshold or combined_risk >= risk_threshold:
                current_seen.add(md5)
                _append_local_hash(md5)
                if md5 in seen:
                    continue
                new_hits += 1
                _record_detection(
                    proc,
                    exe,
                    md5,
                    proba,
                    threshold,
                    combined_risk,
                    risk_threshold,
                    heuristic_reasons,
                    verbose,
                    context,
                )
        except PSUTIL_EXCEPTIONS:
            continue
        except Exception:
            continue
    return current_seen, new_hits


def monitor_loop(
    threshold: float,
    risk_threshold: float,
    interval: int,
    duration: int,
    verbose: bool = False,
) -> int:
    """Continuously scan processes for the requested duration."""
    seen: Set[str] = set()
    total_hits = 0
    end_time = time.time() + duration if duration else None
    baseline_hashes = _load_baseline_hashes()
    while True:
        current_seen, hits = run_scan(
            threshold,
            risk_threshold,
            seen,
            verbose,
            baseline_hashes,
        )
        seen = current_seen
        total_hits += hits
        if end_time is not None and time.time() >= end_time:
            break
        try:
            if end_time is not None:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sleep_for = min(interval, max(1, int(remaining)))
            else:
                sleep_for = interval
            time.sleep(max(1, sleep_for))
        except KeyboardInterrupt:
            break
    return total_hits


def summarize_detections(top: int = 5) -> str:
    """Build a human-readable summary of historical detections."""

    if not DETECTIONS_CSV.exists():
        return "No GA Tech process detections recorded yet."

    process_counts = Counter()
    reason_counts = Counter()
    user_counts = Counter()
    total = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    with DETECTIONS_CSV.open(newline="") as csv_handle:
        reader = csv.DictReader(csv_handle)
        if reader.fieldnames is None:
            return "Detection log is missing headers; unable to summarize."
        for row in reader:
            total += 1
            process = (row.get("process") or row.get("name") or "unknown").strip() or "unknown"
            process_counts[process] += 1
            user = (row.get("username") or "unknown").strip() or "unknown"
            user_counts[user] += 1
            reasons = row.get("reasons", "")
            for reason in reasons.split(";"):
                reason = reason.strip()
                if reason:
                    reason_counts[reason] += 1
            ts = row.get("timestamp")
            if ts:
                if not first_seen or ts < first_seen:
                    first_seen = ts
                if not last_seen or ts > last_seen:
                    last_seen = ts

    if total == 0:
        return "Detection log exists but contains no rows to summarize."

    lines = [SUMMARY_HEADER, f"  Total detections: {total}"]
    if first_seen and last_seen:
        lines.append(f"  Time range: {first_seen} – {last_seen}")
    lines.append("  Top processes:")
    for name, count in process_counts.most_common(max(1, top)):
        lines.append(f"    - {name}: {count}")
    lines.append("  Top usernames:")
    for name, count in user_counts.most_common(max(1, top)):
        lines.append(f"    - {name}: {count}")
    lines.append("  Frequent reasons:")
    for reason, count in reason_counts.most_common(max(1, top)):
        lines.append(f"    - {reason}: {count}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="GA Tech process detector")
    parser.add_argument("--train", action="store_true", help="only train the model")
    parser.add_argument("--scan", action="store_true", help="only scan running processes")
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.getenv("GA_PROC_THRESHOLD", "0.5")),
        help="probability threshold for flagging processes",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=float(os.getenv("GA_PROC_MIN_RISK", "0.6")),
        help="minimum combined risk score required to alert",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="continuously monitor processes instead of a single scan",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.getenv("GA_PROC_INTERVAL", "60")),
        help="seconds to wait between scans when monitoring",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=int(os.getenv("GA_PROC_DURATION", "0")),
        help="number of seconds to monitor before exiting (0 runs until interrupted)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print detections and summaries to stdout",
    )
    parser.add_argument(
        "--refresh-baseline",
        action="store_true",
        help="rebuild the benign baseline from current processes",
    )
    parser.add_argument(
        "--summarize",
        action="store_true",
        help="print a summary of logged detections",
    )
    parser.add_argument(
        "--summary-top",
        type=int,
        default=int(os.getenv("GA_PROC_SUMMARY_TOP", "5")),
        help="how many top entries to list for processes, users, and reasons",
    )
    args = parser.parse_args()

    if args.refresh_baseline:
        refresh_baseline(args.verbose)

    default_actions = not any(
        [args.train, args.scan, args.monitor, args.refresh_baseline, args.summarize]
    )
    do_train = args.train or default_actions
    do_scan = (args.scan or default_actions) and not args.monitor

    if do_train or do_scan or args.monitor:
        download_dataset()

    if do_train:
        train_model()
    if args.monitor:
        hits = monitor_loop(
            args.threshold,
            args.risk_threshold,
            max(1, args.interval),
            max(0, args.duration),
            args.verbose,
        )
        if args.verbose:
            print(f"Monitor finished with {hits} new alert(s)." if hits else "Monitor finished with no new alerts.")
    elif do_scan:
        _, hits = run_scan(args.threshold, args.risk_threshold, verbose=args.verbose)
        if args.verbose:
            if hits:
                print(f"Flagged {hits} process(es) with combined risk >= {args.risk_threshold:.2f}.")
            else:
                print("No processes exceeded the GA Tech risk threshold.")

    if args.summarize:
        print(summarize_detections(max(1, args.summary_top)))


if __name__ == "__main__":
    main()

