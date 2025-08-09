#!/usr/bin/env python3
"""nn_ids_service.py - Monitor network traffic and alert based on NN model."""
import joblib
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import subprocess

MODEL_PATH = "/opt/nnids/ids_model.pkl"

NOTIFY_ENABLED = os.getenv("NN_IDS_NOTIFY", "1") == "1"
DISCOVERY_MODE = os.getenv("NN_IDS_DISCOVERY_MODE", "auto")


MODEL_PATH = "/opt/nnids/ids_model.pkl"

try:
    clf = joblib.load(MODEL_PATH)
except Exception:
    clf = None

benign_counts = defaultdict(int)


def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        return [pkt[IP].len, pkt[IP].ttl, pkt[TCP].dport, int(pkt[TCP].flags)]
    return None


def analyze(pkt):
    if clf is None:
        return
    feats = extract_features(pkt)
    if feats:
        prob = clf.predict_proba([feats])[0][1]
        pred = int(prob >= 0.5)
        key = tuple(feats)
        if pred == 1:
            message = f"Threat ({prob:.2f}): {pkt.summary()}"
            with open('/var/log/nn_ids_alerts.log', 'a') as f:
                if prob >= 0.8:
                    f.write(f'High confidence {message}\n')
                else:
                    f.write(f'Low confidence {message}\n')
            if NOTIFY_ENABLED:
                subprocess.run(["wall", message], check=False)
            if DISCOVERY_MODE == "auto":
                subprocess.Popen(["/usr/local/bin/network_discovery.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif DISCOVERY_MODE == "manual" and NOTIFY_ENABLED:
                subprocess.run(["wall", "Run /usr/local/bin/network_discovery.sh for details"], check=False)
            elif DISCOVERY_MODE == "notify" and NOTIFY_ENABLED:
                subprocess.run(["wall", "Malicious traffic detected"], check=False)
            with open('/var/log/nn_ids_alerts.log', 'a') as f:
                if prob >= 0.8:
                    f.write(f'High confidence threat ({prob:.2f}): {pkt.summary()}\n')
                else:
                    f.write(f'Low confidence threat ({prob:.2f}): {pkt.summary()}\n')
        pred = clf.predict([feats])[0]
        key = tuple(feats)
        if pred == 1:
            with open('/var/log/nn_ids_alerts.log', 'a') as f:
                f.write(f'Suspicious packet: {pkt.summary()}\n')
            benign_counts.pop(key, None)
        else:
            benign_counts[key] += 1
            if benign_counts[key] > 10:
                with open('/var/log/nn_ids_alerts.log', 'a') as f:
                    f.write(f'Possible desensitization attempt: {pkt.summary()}\n')
                benign_counts[key] = 0
        if len(benign_counts) > 1000:
            benign_counts.clear()


def main():
    sniff(prn=analyze, store=0)


if __name__ == '__main__':
    main()
