#!/usr/bin/env python3
"""nn_ids_service.py - Monitor network traffic and alert based on NN model."""
import joblib
from scapy.all import sniff, IP, TCP

MODEL_PATH = "/opt/nnids/ids_model.pkl"

try:
    clf = joblib.load(MODEL_PATH)
except Exception:
    clf = None


def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        return [pkt[IP].len, pkt[IP].ttl, pkt[TCP].dport, int(pkt[TCP].flags)]
    return None


def analyze(pkt):
    if clf is None:
        return
    feats = extract_features(pkt)
    if feats:
        pred = clf.predict([feats])[0]
        if pred == 1:
            with open('/var/log/nn_ids_alerts.log', 'a') as f:
                f.write(f'Suspicious packet: {pkt.summary()}\n')


def main():
    sniff(prn=analyze, store=0)


if __name__ == '__main__':
    main()
