#!/usr/bin/env python3
"""nn_ids_service.py - Monitor network traffic and alert based on NN model."""

from collections import defaultdict
import os
import subprocess

import joblib
from nn_ids_feature_schema import validate_feature_vector
from scapy.all import IP, TCP, sniff

MODEL_PATH = "/opt/nnids/ids_model.pkl"
ALERT_LOG = "/var/log/nn_ids_alerts.log"
NOTIFY_ENABLED = os.getenv("NN_IDS_NOTIFY", "1") == "1"
DISCOVERY_MODE = os.getenv("NN_IDS_DISCOVERY_MODE", "auto")
ALERT_THRESHOLD = float(os.getenv("NN_IDS_ALERT_THRESHOLD", "0.5"))
HIGH_CONFIDENCE_THRESHOLD = float(os.getenv("NN_IDS_HIGH_CONFIDENCE_THRESHOLD", "0.8"))

try:
    clf = joblib.load(MODEL_PATH)
except Exception:
    clf = None

benign_counts = defaultdict(int)


def extract_features(pkt):
    """Extract canonical NN IDS features from a TCP/IP packet."""

    if IP in pkt and TCP in pkt:
        return [pkt[IP].len, pkt[IP].ttl, pkt[TCP].dport, int(pkt[TCP].flags)]
    return None


def log_alert(message: str) -> None:
    with open(ALERT_LOG, "a", encoding="utf-8") as alert_log:
        alert_log.write(f"{message}\n")


def notify(message: str) -> None:
    if NOTIFY_ENABLED:
        subprocess.run(["wall", message], check=False)


def trigger_discovery() -> None:
    if DISCOVERY_MODE == "auto":
        subprocess.Popen(
            ["/usr/local/bin/network_discovery.sh"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif DISCOVERY_MODE == "manual" and NOTIFY_ENABLED:
        subprocess.run(["wall", "Run /usr/local/bin/network_discovery.sh for details"], check=False)
    elif DISCOVERY_MODE == "notify" and NOTIFY_ENABLED:
        subprocess.run(["wall", "Malicious traffic detected"], check=False)


def predict_probability(feats) -> float:
    """Return malicious probability while supporting older estimators."""

    if hasattr(clf, "predict_proba"):
        return float(clf.predict_proba([feats])[0][1])
    return float(clf.predict([feats])[0])


def analyze(pkt):
    if clf is None:
        return

    feats = extract_features(pkt)
    if feats is None:
        return

    check = validate_feature_vector(feats)
    if not check.ok:
        log_alert(f"Dropped invalid feature vector from packet: {'; '.join(check.errors)}")
        return

    probability = predict_probability(feats)
    key = tuple(feats)
    if probability >= ALERT_THRESHOLD:
        confidence = "High" if probability >= HIGH_CONFIDENCE_THRESHOLD else "Low"
        message = f"{confidence} confidence threat ({probability:.2f}): {pkt.summary()}"
        log_alert(message)
        notify(message)
        trigger_discovery()
        benign_counts.pop(key, None)
        return

    benign_counts[key] += 1
    if benign_counts[key] > 10:
        log_alert(f"Possible desensitization attempt: {pkt.summary()}")
        benign_counts[key] = 0
    if len(benign_counts) > 1000:
        benign_counts.clear()


def main():
    sniff(prn=analyze, store=0)


if __name__ == "__main__":
    main()
