#!/usr/bin/env python3
"""nn_ids_capture.py - Capture packet features for NN IDS training."""
from scapy.all import sniff, IP, TCP
from pathlib import Path
import csv

CAPTURE_FILE = Path("/opt/nnids/live_capture.csv")


def extract(pkt):
    if IP in pkt and TCP in pkt:
        return [pkt[IP].len, pkt[IP].ttl, pkt[TCP].dport, int(pkt[TCP].flags), 0]
    return None


def main():
    CAPTURE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with CAPTURE_FILE.open("a", newline="") as f:
        writer = csv.writer(f)
        def process(pkt):
            feats = extract(pkt)
            if feats:
                writer.writerow(feats)
        sniff(count=100, timeout=60, prn=process, store=0)


if __name__ == "__main__":
    main()
